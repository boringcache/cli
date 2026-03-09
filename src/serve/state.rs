use crate::api::client::ApiClient;
use crate::api::models::cache::BlobDescriptor;
use crate::cas_oci::sha256_hex;
use crate::tag_utils::TagResolver;
use dashmap::DashMap;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, Mutex, Notify, RwLock};

pub fn diagnostics_enabled() -> bool {
    log::log_enabled!(log::Level::Debug)
}

#[derive(Clone)]
pub struct AppState {
    pub api_client: ApiClient,
    pub workspace: String,
    pub tag_resolver: TagResolver,
    pub configured_human_tags: Vec<String>,
    pub registry_root_tag: String,
    pub fail_on_cache_error: bool,
    pub kv_manifest_warm_enabled: bool,
    pub blob_locator: Arc<RwLock<BlobLocatorCache>>,
    pub upload_sessions: Arc<RwLock<UploadSessionStore>>,
    pub kv_pending: Arc<RwLock<KvPendingStore>>,
    pub kv_flush_lock: Arc<Mutex<()>>,
    pub kv_lookup_inflight: Arc<DashMap<String, Arc<Notify>>>,
    pub kv_last_put: Arc<AtomicU64>,
    pub kv_backlog_rejects: Arc<AtomicU64>,
    pub kv_replication_enqueue_deferred: Arc<AtomicU64>,
    pub kv_replication_flush_ok: Arc<AtomicU64>,
    pub kv_replication_flush_conflict: Arc<AtomicU64>,
    pub kv_replication_flush_error: Arc<AtomicU64>,
    pub kv_replication_flush_permanent: Arc<AtomicU64>,
    pub kv_replication_queue_depth: Arc<AtomicU64>,
    pub kv_replication_work_tx: mpsc::Sender<KvReplicationWork>,
    pub kv_next_flush_at: Arc<RwLock<Option<Instant>>>,
    pub kv_flush_scheduled: Arc<AtomicBool>,
    pub kv_published_index: Arc<RwLock<KvPublishedIndex>>,
    pub kv_flushing: Arc<RwLock<Option<KvFlushingSnapshot>>>,
    pub kv_recent_misses: Arc<DashMap<String, Instant>>,
    pub kv_miss_generations: Arc<DashMap<String, u64>>,
    pub blob_read_cache: Arc<BlobReadCache>,
    pub blob_download_max_concurrency: usize,
    pub blob_download_semaphore: Arc<tokio::sync::Semaphore>,
    pub blob_prefetch_semaphore: Arc<tokio::sync::Semaphore>,
    pub cache_ops: Arc<super::cache_registry::cache_ops::Aggregator>,
    pub oci_manifest_cache: Arc<DashMap<String, Arc<OciManifestCacheEntry>>>,
    pub backend_breaker: Arc<BackendCircuitBreaker>,
    pub prefetch_complete: Arc<AtomicBool>,
}

const BACKEND_BREAKER_OPEN_DURATION_MS: u64 = 8_000;
const BACKEND_BREAKER_FAILURE_THRESHOLD: u32 = 3;

pub struct BackendCircuitBreaker {
    open_until: AtomicU64,
    consecutive_failures: std::sync::atomic::AtomicU32,
}

impl BackendCircuitBreaker {
    pub fn new() -> Self {
        Self {
            open_until: AtomicU64::new(0),
            consecutive_failures: std::sync::atomic::AtomicU32::new(0),
        }
    }

    pub fn is_open(&self) -> bool {
        let until = self.open_until.load(Ordering::Acquire);
        until > 0 && unix_time_ms_now() < until
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Release);
        self.open_until.store(0, Ordering::Release);
    }

    pub fn record_failure(&self) {
        let prev = self.consecutive_failures.fetch_add(1, Ordering::AcqRel);
        if prev + 1 >= BACKEND_BREAKER_FAILURE_THRESHOLD {
            let until = unix_time_ms_now() + BACKEND_BREAKER_OPEN_DURATION_MS;
            self.open_until.store(until, Ordering::Release);
        }
    }
}

impl Default for BackendCircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

pub const DEFAULT_BLOB_READ_CACHE_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const OCI_MANIFEST_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const BLOB_READ_CACHE_DIR_NAME: &str = "boringcache-blob-cache";
const BLOB_READ_SEGMENTS_DIR_NAME: &str = "segments";
const BLOB_READ_SEGMENT_PREFIX: &str = "segment-";
const BLOB_READ_SEGMENT_SUFFIX: &str = ".log";
const BLOB_READ_SEGMENT_RECORD_MAGIC: [u8; 4] = *b"BCB1";
const BLOB_READ_SEGMENT_HEADER_BYTES: usize = 4 + 8 + 64;
const BLOB_READ_SEGMENT_MAX_BYTES: u64 = 256 * 1024 * 1024;
const BLOB_READ_FLIGHT_WAIT_WARN_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(not(test))]
const BLOB_READ_FLIGHT_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(test)]
const BLOB_READ_FLIGHT_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);

pub struct OciManifestCacheEntry {
    pub index_json: Vec<u8>,
    pub content_type: String,
    pub manifest_digest: String,
    pub cache_entry_id: String,
    pub blobs: Vec<BlobDescriptor>,
    pub name: String,
    pub inserted_at: Instant,
}

struct BlobReadInFlightGuard {
    key: String,
    notify: Arc<Notify>,
    inflight: Arc<DashMap<String, Arc<Notify>>>,
}

impl Drop for BlobReadInFlightGuard {
    fn drop(&mut self) {
        self.inflight.remove(&self.key);
        self.notify.notify_waiters();
    }
}

enum BlobReadInFlight {
    Leader(BlobReadInFlightGuard),
    Follower(std::pin::Pin<Box<tokio::sync::futures::OwnedNotified>>),
}

#[derive(Debug, Clone)]
pub struct BlobReadHandle {
    path: PathBuf,
    offset: u64,
    size_bytes: u64,
}

impl BlobReadHandle {
    pub fn from_file(path: PathBuf, size_bytes: u64) -> Self {
        Self {
            path,
            offset: 0,
            size_bytes,
        }
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

#[derive(Debug, Clone)]
enum BlobReadStorageEntry {
    LegacyFile {
        path: PathBuf,
        size_bytes: u64,
    },
    Segment {
        segment_id: u64,
        path: PathBuf,
        offset: u64,
        size_bytes: u64,
    },
}

#[derive(Debug, Clone)]
struct BlobReadSegmentMeta {
    path: PathBuf,
    size_bytes: u64,
}

#[derive(Debug)]
struct BlobReadSegmentState {
    segments_dir: PathBuf,
    segments: BTreeMap<u64, BlobReadSegmentMeta>,
    active_segment_id: Option<u64>,
}

pub struct BlobReadCache {
    cache_dir: PathBuf,
    total_bytes: AtomicU64,
    max_bytes: u64,
    inflight: Arc<DashMap<String, Arc<Notify>>>,
    storage_index: Arc<DashMap<String, BlobReadStorageEntry>>,
    segment_entry_keys: Arc<DashMap<u64, Vec<String>>>,
    segment_state: Arc<Mutex<BlobReadSegmentState>>,
    append_lock: Arc<Mutex<()>>,
    evict_lock: Arc<Mutex<()>>,
}

impl BlobReadCache {
    pub fn new(max_bytes: u64) -> io::Result<Self> {
        let cache_dir = std::env::temp_dir().join(BLOB_READ_CACHE_DIR_NAME);
        Self::new_at(cache_dir, max_bytes)
    }

    pub fn new_at(cache_dir: PathBuf, max_bytes: u64) -> io::Result<Self> {
        std::fs::create_dir_all(&cache_dir)?;
        let segments_dir = cache_dir.join(BLOB_READ_SEGMENTS_DIR_NAME);
        std::fs::create_dir_all(&segments_dir)?;

        let (index_entries, segment_state, total_bytes) =
            Self::scan_storage(&cache_dir, &segments_dir)?;

        let storage_index = Arc::new(DashMap::new());
        let segment_entry_keys: DashMap<u64, Vec<String>> = DashMap::new();
        for (key, entry) in index_entries {
            if let BlobReadStorageEntry::Segment { segment_id, .. } = &entry {
                segment_entry_keys
                    .entry(*segment_id)
                    .or_default()
                    .push(key.clone());
            }
            storage_index.insert(key, entry);
        }

        Ok(Self {
            cache_dir,
            total_bytes: AtomicU64::new(total_bytes),
            max_bytes: max_bytes.max(1),
            inflight: Arc::new(DashMap::new()),
            storage_index,
            segment_entry_keys: Arc::new(segment_entry_keys),
            segment_state: Arc::new(Mutex::new(segment_state)),
            append_lock: Arc::new(Mutex::new(())),
            evict_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn cache_dir(&self) -> &Path {
        self.cache_dir.as_path()
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes.load(Ordering::Acquire)
    }

    async fn await_blob_read_flight(
        &self,
        key: &str,
        notified: std::pin::Pin<Box<tokio::sync::futures::OwnedNotified>>,
    ) -> bool {
        let started = Instant::now();
        match tokio::time::timeout(BLOB_READ_FLIGHT_WAIT_TIMEOUT, notified).await {
            Ok(()) => {
                let elapsed = started.elapsed();
                if elapsed >= BLOB_READ_FLIGHT_WAIT_WARN_THRESHOLD {
                    log::warn!(
                        "blob read follower waited {}ms for key={}",
                        elapsed.as_millis(),
                        &key[..key.len().min(24)],
                    );
                }
                true
            }
            Err(_) => {
                log::warn!(
                    "blob read follower timed out after {}ms for key={}",
                    started.elapsed().as_millis(),
                    &key[..key.len().min(24)],
                );
                false
            }
        }
    }

    fn clear_blob_read_inflight(&self, key: &str) {
        self.inflight.remove(key);
    }

    fn track_storage_entry(&self, key: String, entry: BlobReadStorageEntry) {
        if let BlobReadStorageEntry::Segment { segment_id, .. } = &entry {
            self.segment_entry_keys
                .entry(*segment_id)
                .or_default()
                .push(key.clone());
        }
        self.storage_index.insert(key, entry);
    }

    pub async fn get_handle(&self, digest: &str) -> Option<BlobReadHandle> {
        let key = Self::normalize_digest_hex(digest)?;
        let entry = self
            .storage_index
            .get(&key)
            .map(|item| item.value().clone())?;
        match entry {
            BlobReadStorageEntry::LegacyFile { path, size_bytes } => {
                let metadata = tokio::fs::metadata(&path).await.ok()?;
                if !metadata.is_file() || metadata.len() == 0 {
                    self.storage_index.remove(&key);
                    return None;
                }
                let size = if size_bytes > 0 {
                    size_bytes.min(metadata.len())
                } else {
                    metadata.len()
                };
                Some(BlobReadHandle {
                    path,
                    offset: 0,
                    size_bytes: size,
                })
            }
            BlobReadStorageEntry::Segment {
                segment_id: _,
                path,
                offset,
                size_bytes,
            } => {
                if size_bytes == 0 {
                    self.storage_index.remove(&key);
                    return None;
                }
                Some(BlobReadHandle {
                    path,
                    offset,
                    size_bytes,
                })
            }
        }
    }

    pub async fn get(&self, digest: &str) -> Option<PathBuf> {
        let handle = self.get_handle(digest).await?;
        if handle.offset == 0 {
            return Some(handle.path);
        }
        None
    }

    pub async fn remove(&self, digest: &str) {
        let Some(key) = Self::normalize_digest_hex(digest) else {
            return;
        };
        let Some((_, entry)) = self.storage_index.remove(&key) else {
            return;
        };
        if let BlobReadStorageEntry::LegacyFile { path, size_bytes } = entry {
            let _ = tokio::fs::remove_file(&path).await;
            self.sub_total(size_bytes);
        }
    }

    pub async fn insert(&self, digest: &str, data: &[u8]) -> io::Result<bool> {
        if data.is_empty() {
            return Ok(false);
        }
        let Some(key) = Self::normalize_digest_hex(digest) else {
            return Ok(false);
        };

        if self.get_handle(&key).await.is_some() {
            return Ok(false);
        }

        match self.begin_inflight(key.clone()) {
            BlobReadInFlight::Follower(notify) => {
                if !self.await_blob_read_flight(&key, notify).await {
                    self.clear_blob_read_inflight(&key);
                }
                Ok(false)
            }
            BlobReadInFlight::Leader(_guard) => {
                if self.get_handle(&key).await.is_some() {
                    return Ok(false);
                }

                let Some(entry) = self.append_blob_bytes(&key, data).await? else {
                    return Ok(false);
                };
                self.track_storage_entry(key, entry);
                if let Err(error) = self.evict_over_budget().await {
                    log::warn!("Blob read cache eviction failed after insert: {error}");
                }
                Ok(true)
            }
        }
    }

    pub async fn promote(
        &self,
        digest: &str,
        src_path: &Path,
        size_bytes: u64,
    ) -> io::Result<bool> {
        let Some(key) = Self::normalize_digest_hex(digest) else {
            return Ok(false);
        };

        let src_metadata = match tokio::fs::metadata(src_path).await {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };

        let source_size = if size_bytes > 0 {
            size_bytes
        } else {
            src_metadata.len()
        };
        if source_size == 0 {
            let _ = tokio::fs::remove_file(src_path).await;
            return Ok(false);
        }

        if self.get_handle(&key).await.is_some() {
            let _ = tokio::fs::remove_file(src_path).await;
            return Ok(false);
        }

        match self.begin_inflight(key.clone()) {
            BlobReadInFlight::Follower(notify) => {
                if !self.await_blob_read_flight(&key, notify).await {
                    self.clear_blob_read_inflight(&key);
                }
                let _ = tokio::fs::remove_file(src_path).await;
                Ok(false)
            }
            BlobReadInFlight::Leader(_guard) => {
                if self.get_handle(&key).await.is_some() {
                    let _ = tokio::fs::remove_file(src_path).await;
                    return Ok(false);
                }

                let Some(entry) = self
                    .append_blob_from_file(&key, src_path, source_size)
                    .await?
                else {
                    return Ok(false);
                };
                self.track_storage_entry(key, entry);
                let _ = tokio::fs::remove_file(src_path).await;
                if let Err(error) = self.evict_over_budget().await {
                    log::warn!("Blob read cache eviction failed after promote: {error}");
                }
                Ok(true)
            }
        }
    }

    async fn append_blob_bytes(
        &self,
        digest_hex: &str,
        data: &[u8],
    ) -> io::Result<Option<BlobReadStorageEntry>> {
        let _append_guard = self.append_lock.lock().await;
        let data_len = data.len() as u64;
        let (segment_id, path, data_offset) = self.prepare_segment_write(data_len).await?;

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        let header = Self::build_segment_header(digest_hex, data_len)?;
        tokio::io::AsyncWriteExt::write_all(&mut file, &header).await?;
        tokio::io::AsyncWriteExt::write_all(&mut file, data).await?;
        tokio::io::AsyncWriteExt::flush(&mut file).await?;
        drop(file);

        let written = BLOB_READ_SEGMENT_HEADER_BYTES as u64 + data_len;
        self.finish_segment_write(segment_id, written).await;
        Ok(Some(BlobReadStorageEntry::Segment {
            segment_id,
            path,
            offset: data_offset,
            size_bytes: data_len,
        }))
    }

    async fn append_blob_from_file(
        &self,
        digest_hex: &str,
        src_path: &Path,
        size_bytes: u64,
    ) -> io::Result<Option<BlobReadStorageEntry>> {
        let _append_guard = self.append_lock.lock().await;
        let (segment_id, path, data_offset) = self.prepare_segment_write(size_bytes).await?;

        let mut dst = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        let header = Self::build_segment_header(digest_hex, size_bytes)?;
        tokio::io::AsyncWriteExt::write_all(&mut dst, &header).await?;
        let mut src = tokio::fs::File::open(src_path).await?;
        let copied = tokio::io::copy(&mut src, &mut dst).await?;
        if copied == 0 {
            return Ok(None);
        }
        tokio::io::AsyncWriteExt::flush(&mut dst).await?;
        drop(dst);

        let written = BLOB_READ_SEGMENT_HEADER_BYTES as u64 + copied;
        self.finish_segment_write(segment_id, written).await;
        Ok(Some(BlobReadStorageEntry::Segment {
            segment_id,
            path,
            offset: data_offset,
            size_bytes: copied,
        }))
    }

    async fn prepare_segment_write(&self, data_len: u64) -> io::Result<(u64, PathBuf, u64)> {
        let record_bytes = BLOB_READ_SEGMENT_HEADER_BYTES as u64 + data_len;
        let mut state = self.segment_state.lock().await;
        let segment_limit = BLOB_READ_SEGMENT_MAX_BYTES.min(self.max_bytes.max(1));

        let mut active_id = state.active_segment_id.unwrap_or(0);
        if active_id == 0 {
            active_id = 1;
            let path = Self::segment_path_for_id(&state.segments_dir, active_id);
            state.segments.insert(
                active_id,
                BlobReadSegmentMeta {
                    path,
                    size_bytes: 0,
                },
            );
            state.active_segment_id = Some(active_id);
        }

        let active_size = state
            .segments
            .get(&active_id)
            .map(|meta| meta.size_bytes)
            .unwrap_or(0);
        if active_size > 0 && active_size.saturating_add(record_bytes) > segment_limit {
            let next_id = active_id.saturating_add(1);
            let path = Self::segment_path_for_id(&state.segments_dir, next_id);
            state.segments.insert(
                next_id,
                BlobReadSegmentMeta {
                    path,
                    size_bytes: 0,
                },
            );
            state.active_segment_id = Some(next_id);
            active_id = next_id;
        }

        let meta = state
            .segments
            .get(&active_id)
            .cloned()
            .ok_or_else(|| io::Error::other("missing active segment metadata"))?;
        let data_offset = meta.size_bytes + BLOB_READ_SEGMENT_HEADER_BYTES as u64;
        Ok((active_id, meta.path, data_offset))
    }

    async fn finish_segment_write(&self, segment_id: u64, written_bytes: u64) {
        let mut state = self.segment_state.lock().await;
        if let Some(meta) = state.segments.get_mut(&segment_id) {
            meta.size_bytes = meta.size_bytes.saturating_add(written_bytes);
        }
        self.total_bytes.fetch_add(written_bytes, Ordering::AcqRel);
    }

    async fn evict_over_budget(&self) -> io::Result<()> {
        if self.total_bytes.load(Ordering::Acquire) <= self.max_bytes {
            return Ok(());
        }

        let _guard = self.evict_lock.lock().await;
        if self.total_bytes.load(Ordering::Acquire) <= self.max_bytes {
            return Ok(());
        }

        let mut total = self.total_bytes.load(Ordering::Acquire);

        let mut legacy_files: Vec<(std::time::SystemTime, String, PathBuf, u64)> = Vec::new();
        for entry in self.storage_index.iter() {
            if let BlobReadStorageEntry::LegacyFile { path, size_bytes } = entry.value() {
                let modified = tokio::fs::metadata(path)
                    .await
                    .ok()
                    .and_then(|meta| meta.modified().ok())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                legacy_files.push((modified, entry.key().clone(), path.clone(), *size_bytes));
            }
        }
        legacy_files.sort_by_key(|(modified, _, _, _)| *modified);
        for (_, digest, path, size_bytes) in legacy_files {
            if total <= self.max_bytes {
                break;
            }
            if tokio::fs::remove_file(&path).await.is_ok() {
                self.storage_index.remove(&digest);
                total = total.saturating_sub(size_bytes);
            }
        }

        if total > self.max_bytes {
            let mut state = self.segment_state.lock().await;
            let active_id = state.active_segment_id;
            let removable: Vec<u64> = state
                .segments
                .keys()
                .copied()
                .filter(|id| Some(*id) != active_id)
                .collect();
            for segment_id in removable {
                if total <= self.max_bytes {
                    break;
                }
                let Some(meta) = state.segments.remove(&segment_id) else {
                    continue;
                };
                if tokio::fs::remove_file(&meta.path).await.is_ok() {
                    if let Some((_, keys)) = self.segment_entry_keys.remove(&segment_id) {
                        for key in keys {
                            self.storage_index.remove(&key);
                        }
                    }
                    total = total.saturating_sub(meta.size_bytes);
                }
            }
        }

        self.total_bytes.store(total, Ordering::Release);
        Ok(())
    }

    fn scan_storage(
        cache_dir: &Path,
        segments_dir: &Path,
    ) -> io::Result<(
        HashMap<String, BlobReadStorageEntry>,
        BlobReadSegmentState,
        u64,
    )> {
        let mut total_bytes = 0u64;
        let mut entries = HashMap::new();

        for entry in std::fs::read_dir(cache_dir)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = match entry.metadata() {
                Ok(meta) if meta.is_file() => meta,
                _ => continue,
            };
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if let Some(key) = Self::legacy_digest_key_from_name(file_name) {
                if metadata.len() > 0 {
                    total_bytes = total_bytes.saturating_add(metadata.len());
                    entries.insert(
                        key,
                        BlobReadStorageEntry::LegacyFile {
                            path,
                            size_bytes: metadata.len(),
                        },
                    );
                }
            }
        }

        let mut segments = BTreeMap::new();
        if segments_dir.exists() {
            for entry in std::fs::read_dir(segments_dir)? {
                let entry = entry?;
                let path = entry.path();
                let metadata = match entry.metadata() {
                    Ok(meta) if meta.is_file() => meta,
                    _ => continue,
                };
                let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                let Some(segment_id) = Self::parse_segment_id(file_name) else {
                    continue;
                };
                total_bytes = total_bytes.saturating_add(metadata.len());
                segments.insert(
                    segment_id,
                    BlobReadSegmentMeta {
                        path,
                        size_bytes: metadata.len(),
                    },
                );
            }
        }

        for (segment_id, meta) in &segments {
            Self::scan_segment_file(*segment_id, meta, &mut entries)?;
        }

        let active_segment_id = segments.keys().next_back().copied();
        Ok((
            entries,
            BlobReadSegmentState {
                segments_dir: segments_dir.to_path_buf(),
                segments,
                active_segment_id,
            },
            total_bytes,
        ))
    }

    fn scan_segment_file(
        segment_id: u64,
        meta: &BlobReadSegmentMeta,
        entries: &mut HashMap<String, BlobReadStorageEntry>,
    ) -> io::Result<()> {
        use std::io::{Read, Seek, SeekFrom};

        let mut file = std::fs::File::open(&meta.path)?;
        let file_len = file.metadata()?.len();
        let mut offset = 0u64;

        loop {
            if offset.saturating_add(BLOB_READ_SEGMENT_HEADER_BYTES as u64) > file_len {
                break;
            }

            let mut header = [0u8; BLOB_READ_SEGMENT_HEADER_BYTES];
            if let Err(error) = file.read_exact(&mut header) {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(error);
            }
            if header[..4] != BLOB_READ_SEGMENT_RECORD_MAGIC {
                break;
            }

            let size_bytes = u64::from_le_bytes(
                header[4..12]
                    .try_into()
                    .map_err(|_| io::Error::other("invalid segment header size bytes"))?,
            );
            if size_bytes == 0 {
                break;
            }

            let digest_bytes = &header[12..];
            if digest_bytes.len() != 64 || !digest_bytes.iter().all(|byte| byte.is_ascii_hexdigit())
            {
                break;
            }
            let digest = String::from_utf8_lossy(digest_bytes).to_ascii_lowercase();

            let data_offset = offset + BLOB_READ_SEGMENT_HEADER_BYTES as u64;
            let next = data_offset.saturating_add(size_bytes);
            if next > file_len {
                break;
            }

            entries.insert(
                digest,
                BlobReadStorageEntry::Segment {
                    segment_id,
                    path: meta.path.clone(),
                    offset: data_offset,
                    size_bytes,
                },
            );
            file.seek(SeekFrom::Start(next))?;
            offset = next;
        }

        Ok(())
    }

    fn build_segment_header(
        digest_hex: &str,
        size_bytes: u64,
    ) -> io::Result<[u8; BLOB_READ_SEGMENT_HEADER_BYTES]> {
        if digest_hex.len() != 64 || !digest_hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid digest for segment header",
            ));
        }

        let mut header = [0u8; BLOB_READ_SEGMENT_HEADER_BYTES];
        header[..4].copy_from_slice(&BLOB_READ_SEGMENT_RECORD_MAGIC);
        header[4..12].copy_from_slice(&size_bytes.to_le_bytes());
        header[12..].copy_from_slice(digest_hex.as_bytes());
        Ok(header)
    }

    fn segment_path_for_id(segments_dir: &Path, segment_id: u64) -> PathBuf {
        segments_dir.join(format!(
            "{BLOB_READ_SEGMENT_PREFIX}{segment_id:016x}{BLOB_READ_SEGMENT_SUFFIX}"
        ))
    }

    fn parse_segment_id(file_name: &str) -> Option<u64> {
        if !file_name.starts_with(BLOB_READ_SEGMENT_PREFIX)
            || !file_name.ends_with(BLOB_READ_SEGMENT_SUFFIX)
        {
            return None;
        }
        let middle = &file_name
            [BLOB_READ_SEGMENT_PREFIX.len()..file_name.len() - BLOB_READ_SEGMENT_SUFFIX.len()];
        if middle.is_empty() || !middle.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        u64::from_str_radix(middle, 16).ok()
    }

    fn legacy_digest_key_from_name(name: &str) -> Option<String> {
        if name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Some(name.to_ascii_lowercase());
        }
        None
    }

    fn begin_inflight(&self, key: String) -> BlobReadInFlight {
        match self.inflight.entry(key.clone()) {
            dashmap::mapref::entry::Entry::Occupied(existing) => {
                let mut notified = Box::pin(existing.get().clone().notified_owned());
                notified.as_mut().enable();
                BlobReadInFlight::Follower(notified)
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                let notify = Arc::new(Notify::new());
                entry.insert(notify.clone());
                BlobReadInFlight::Leader(BlobReadInFlightGuard {
                    key,
                    notify,
                    inflight: self.inflight.clone(),
                })
            }
        }
    }

    fn normalize_digest_hex(digest: &str) -> Option<String> {
        let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        Some(hex.to_ascii_lowercase())
    }

    fn sub_total(&self, amount: u64) {
        let mut current = self.total_bytes.load(Ordering::Acquire);
        loop {
            let next = current.saturating_sub(amount);
            match self.total_bytes.compare_exchange(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlobLocatorEntry {
    pub cache_entry_id: String,
    pub size_bytes: u64,
    pub download_url: Option<String>,
    pub download_url_cached_at: Option<Instant>,
}

#[derive(Default)]
pub struct BlobLocatorCache {
    entries: HashMap<String, BlobLocatorEntry>,
}

impl BlobLocatorCache {
    fn key(name: &str, digest: &str) -> String {
        format!("{}\0{}", name, digest)
    }

    pub fn insert(&mut self, name: &str, digest: &str, entry: BlobLocatorEntry) {
        self.entries.insert(Self::key(name, digest), entry);
    }

    pub fn get(&self, name: &str, digest: &str) -> Option<&BlobLocatorEntry> {
        self.entries.get(&Self::key(name, digest))
    }

    pub fn get_mut(&mut self, name: &str, digest: &str) -> Option<&mut BlobLocatorEntry> {
        self.entries.get_mut(&Self::key(name, digest))
    }
}

pub struct UploadSession {
    pub id: String,
    pub name: String,
    pub temp_path: PathBuf,
    pub write_lock: Arc<Mutex<()>>,
    pub bytes_received: u64,
    pub finalized_digest: Option<String>,
    pub finalized_size: Option<u64>,
    pub created_at: Instant,
}

#[derive(Default)]
pub struct UploadSessionStore {
    sessions: HashMap<String, UploadSession>,
}

impl UploadSessionStore {
    pub fn create(&mut self, session: UploadSession) {
        self.sessions.insert(session.id.clone(), session);
    }

    pub fn get(&self, id: &str) -> Option<&UploadSession> {
        self.sessions.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut UploadSession> {
        self.sessions.get_mut(id)
    }

    pub fn remove(&mut self, id: &str) -> Option<UploadSession> {
        self.sessions.remove(id)
    }

    pub fn cleanup_expired(&mut self, max_age: std::time::Duration) -> Vec<UploadSession> {
        let now = Instant::now();
        let expired_keys: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| now.duration_since(s.created_at) >= max_age)
            .map(|(k, _)| k.clone())
            .collect();
        expired_keys
            .iter()
            .filter_map(|k| self.sessions.remove(k))
            .collect()
    }

    pub fn find_by_digest(&self, digest: &str) -> Option<&UploadSession> {
        self.sessions
            .values()
            .filter(|s| s.finalized_digest.as_deref() == Some(digest))
            .max_by_key(|s| s.finalized_size.unwrap_or(s.bytes_received))
    }
}

const DEFAULT_MAX_SPOOL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SPOOL_BYTES_ENV: &str = "BORINGCACHE_MAX_SPOOL_BYTES";

pub fn max_spool_bytes() -> u64 {
    std::env::var(MAX_SPOOL_BYTES_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(DEFAULT_MAX_SPOOL_BYTES)
}

const DEFAULT_FLUSH_BLOB_THRESHOLD: usize = 500;
const FLUSH_BLOB_THRESHOLD_ENV: &str = "BORINGCACHE_FLUSH_BLOB_THRESHOLD";

pub fn flush_blob_threshold() -> usize {
    std::env::var(FLUSH_BLOB_THRESHOLD_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(DEFAULT_FLUSH_BLOB_THRESHOLD)
}

pub const FLUSH_SIZE_THRESHOLD: u64 = 256 * 1024 * 1024;
pub const KV_BACKLOG_POLICY: &str = "reject_when_spool_full";
pub const KV_REPLICATION_WORK_QUEUE_CAPACITY: usize = 5_000;

#[derive(Clone, Copy, Debug)]
pub enum KvReplicationWork {
    FlushHint { urgent: bool },
}

pub(crate) fn unix_time_ms_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Default)]
pub struct KvPendingStore {
    entries: BTreeMap<String, BlobDescriptor>,
    blob_refs: HashMap<String, BlobRef>,
    total_spool_bytes: u64,
    oldest_entry_unix_ms: Option<u64>,
    next_blob_sequence: u64,
}

struct BlobRef {
    path: PathBuf,
    size_bytes: u64,
    refcount: u32,
    first_seen_sequence: u64,
}

impl KvPendingStore {
    pub fn insert(
        &mut self,
        scoped_key: String,
        blob: BlobDescriptor,
        temp_path: PathBuf,
    ) -> Option<PathBuf> {
        let was_empty = self.entries.is_empty();
        if let Some(old) = self.entries.get(&scoped_key) {
            if old.digest == blob.digest {
                return Some(temp_path);
            }
            self.dec_ref(&old.digest.clone());
        }

        let redundant_path = match self.blob_refs.get_mut(&blob.digest) {
            Some(existing) => {
                existing.refcount += 1;
                Some(temp_path)
            }
            None => {
                let spool_limit = max_spool_bytes();
                if self.total_spool_bytes + blob.size_bytes > spool_limit {
                    log::warn!(
                        "KV spool budget exceeded before insert ({} + {} > {}, policy={})",
                        self.total_spool_bytes,
                        blob.size_bytes,
                        spool_limit,
                        KV_BACKLOG_POLICY
                    );
                }
                self.total_spool_bytes += blob.size_bytes;
                let sequence = self.next_blob_sequence;
                self.next_blob_sequence = self.next_blob_sequence.saturating_add(1);
                self.blob_refs.insert(
                    blob.digest.clone(),
                    BlobRef {
                        path: temp_path,
                        size_bytes: blob.size_bytes,
                        refcount: 1,
                        first_seen_sequence: sequence,
                    },
                );
                None
            }
        };

        self.entries.insert(scoped_key, blob);
        if was_empty && !self.entries.is_empty() {
            self.oldest_entry_unix_ms = Some(unix_time_ms_now());
        }
        redundant_path
    }

    fn dec_ref(&mut self, digest: &str) -> Option<PathBuf> {
        let remove = match self.blob_refs.get_mut(digest) {
            Some(bref) => {
                bref.refcount = bref.refcount.saturating_sub(1);
                bref.refcount == 0
            }
            None => false,
        };
        if remove {
            if let Some(bref) = self.blob_refs.remove(digest) {
                self.total_spool_bytes = self.total_spool_bytes.saturating_sub(bref.size_bytes);
                return Some(bref.path);
            }
        }
        None
    }

    pub fn get(&self, scoped_key: &str) -> Option<&BlobDescriptor> {
        self.entries.get(scoped_key)
    }

    pub fn blob_path(&self, digest: &str) -> Option<&PathBuf> {
        self.blob_refs.get(digest).map(|b| &b.path)
    }

    pub fn take_all(
        &mut self,
    ) -> (
        BTreeMap<String, BlobDescriptor>,
        HashMap<String, PathBuf>,
        HashMap<String, u64>,
    ) {
        let entries = std::mem::take(&mut self.entries);
        let mut blob_paths = HashMap::new();
        let mut blob_sequences = HashMap::new();
        for (digest, bref) in self.blob_refs.drain() {
            blob_sequences.insert(digest.clone(), bref.first_seen_sequence);
            blob_paths.insert(digest, bref.path);
        }
        self.total_spool_bytes = 0;
        self.oldest_entry_unix_ms = None;
        (entries, blob_paths, blob_sequences)
    }

    pub fn restore(
        &mut self,
        entries: BTreeMap<String, BlobDescriptor>,
        blob_paths: HashMap<String, PathBuf>,
        blob_sequences: HashMap<String, u64>,
    ) -> Vec<PathBuf> {
        let was_empty = self.entries.is_empty();
        let mut cleanup_paths = Vec::new();
        let mut restore_refcounts: HashMap<String, u32> = HashMap::new();
        for (key, blob) in &entries {
            if let std::collections::btree_map::Entry::Vacant(e) = self.entries.entry(key.clone()) {
                e.insert(blob.clone());
                *restore_refcounts.entry(blob.digest.clone()).or_default() += 1;
            }
        }

        for (digest, count) in &restore_refcounts {
            if let Some(path) = blob_paths.get(digest) {
                match self.blob_refs.get_mut(digest) {
                    Some(existing) => {
                        existing.refcount += count;
                        cleanup_paths.push(path.clone());
                    }
                    None => {
                        let size = entries
                            .values()
                            .find(|b| &b.digest == digest)
                            .map(|b| b.size_bytes)
                            .unwrap_or(0);
                        self.total_spool_bytes += size;
                        self.blob_refs.insert(
                            digest.clone(),
                            BlobRef {
                                path: path.clone(),
                                size_bytes: size,
                                refcount: *count,
                                first_seen_sequence: blob_sequences
                                    .get(digest)
                                    .copied()
                                    .unwrap_or_else(|| {
                                        let sequence = self.next_blob_sequence;
                                        self.next_blob_sequence =
                                            self.next_blob_sequence.saturating_add(1);
                                        sequence
                                    }),
                            },
                        );
                    }
                }
            }
        }

        for (digest, path) in &blob_paths {
            if !restore_refcounts.contains_key(digest) {
                cleanup_paths.push(path.clone());
            }
        }
        if was_empty && !self.entries.is_empty() {
            self.oldest_entry_unix_ms = Some(unix_time_ms_now());
        }
        if let Some(max_sequence) = self
            .blob_refs
            .values()
            .map(|bref| bref.first_seen_sequence)
            .max()
        {
            self.next_blob_sequence = self.next_blob_sequence.max(max_sequence.saturating_add(1));
        }
        cleanup_paths
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn blob_count(&self) -> usize {
        self.blob_refs.len()
    }

    pub fn total_spool_bytes(&self) -> u64 {
        self.total_spool_bytes
    }

    pub fn oldest_entry_age_ms(&self, now_ms: u64) -> Option<u64> {
        self.oldest_entry_unix_ms
            .map(|oldest| now_ms.saturating_sub(oldest))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

pub struct KvFlushingSnapshot {
    entries: BTreeMap<String, BlobDescriptor>,
    blob_paths: HashMap<String, PathBuf>,
}

impl KvFlushingSnapshot {
    pub fn new(
        entries: BTreeMap<String, BlobDescriptor>,
        blob_paths: HashMap<String, PathBuf>,
    ) -> Self {
        Self {
            entries,
            blob_paths,
        }
    }

    pub fn get(&self, scoped_key: &str) -> Option<&BlobDescriptor> {
        self.entries.get(scoped_key)
    }

    pub fn blob_path(&self, digest: &str) -> Option<&PathBuf> {
        self.blob_paths.get(digest)
    }
}

pub const DOWNLOAD_URL_TTL: std::time::Duration = std::time::Duration::from_secs(45 * 60);

struct CachedUrl {
    url: String,
    expires_at: Instant,
}

#[derive(Default)]
pub struct KvPublishedIndex {
    entries: Arc<HashMap<String, BlobDescriptor>>,
    blob_order: Arc<Vec<BlobDescriptor>>,
    cache_entry_id: Option<String>,
    download_urls: HashMap<String, CachedUrl>,
    complete: bool,
    last_refresh_at: Option<Instant>,
}

impl KvPublishedIndex {
    pub fn update(
        &mut self,
        entries: HashMap<String, BlobDescriptor>,
        blob_order: Vec<BlobDescriptor>,
        cache_entry_id: String,
    ) {
        let now = Instant::now();
        let cache_entry_changed = self.cache_entry_id.as_deref() != Some(cache_entry_id.as_str());
        let active_digests: HashSet<String> =
            entries.values().map(|blob| blob.digest.clone()).collect();
        let normalized_blob_order = Self::normalize_blob_order(&entries, blob_order);
        self.entries = Arc::new(entries);
        self.blob_order = Arc::new(normalized_blob_order);
        self.cache_entry_id = Some(cache_entry_id);
        if cache_entry_changed {
            self.download_urls.clear();
        } else {
            self.download_urls.retain(|digest, cached| {
                cached.expires_at > now && active_digests.contains(digest)
            });
        }
        self.complete = true;
        self.last_refresh_at = Some(now);
    }

    pub fn insert(&mut self, scoped_key: String, blob: BlobDescriptor, cache_entry_id: String) {
        let cache_entry_changed = self.cache_entry_id.as_deref() != Some(cache_entry_id.as_str());
        if cache_entry_changed {
            self.download_urls.clear();
            self.cache_entry_id = Some(cache_entry_id);
            self.entries = Arc::new(HashMap::new());
            self.blob_order = Arc::new(Vec::new());
        }

        let entries = Arc::make_mut(&mut self.entries);
        let digest = blob.digest.clone();
        entries.insert(scoped_key, blob.clone());
        let has_digest = self
            .blob_order
            .iter()
            .any(|existing| existing.digest == digest);
        if !has_digest {
            let order = Arc::make_mut(&mut self.blob_order);
            order.push(blob);
        }
        self.complete = false;
        self.last_refresh_at = Some(Instant::now());
    }

    pub fn set_empty(&mut self) {
        self.entries = Arc::new(HashMap::new());
        self.blob_order = Arc::new(Vec::new());
        self.cache_entry_id = None;
        self.download_urls.clear();
        self.complete = true;
        self.last_refresh_at = Some(Instant::now());
    }

    pub fn set_empty_incomplete(&mut self) {
        self.entries = Arc::new(HashMap::new());
        self.blob_order = Arc::new(Vec::new());
        self.cache_entry_id = None;
        self.download_urls.clear();
        self.complete = false;
        self.last_refresh_at = None;
    }

    pub fn set_download_urls(&mut self, urls: HashMap<String, String>) {
        let expires_at = Instant::now() + DOWNLOAD_URL_TTL;
        self.download_urls = urls
            .into_iter()
            .map(|(digest, url)| (digest, CachedUrl { url, expires_at }))
            .collect();
    }

    pub fn set_download_url(&mut self, digest: String, url: String) {
        let expires_at = Instant::now() + DOWNLOAD_URL_TTL;
        self.download_urls
            .insert(digest, CachedUrl { url, expires_at });
    }

    pub fn get(&self, scoped_key: &str) -> Option<(&BlobDescriptor, &str)> {
        let blob = self.entries.get(scoped_key)?;
        let cache_entry_id = self.cache_entry_id.as_deref()?;
        Some((blob, cache_entry_id))
    }

    pub fn download_url(&self, digest: &str) -> Option<&str> {
        let cached = self.download_urls.get(digest)?;
        if Instant::now() >= cached.expires_at {
            return None;
        }
        Some(&cached.url)
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn unique_blobs(&self) -> Vec<BlobDescriptor> {
        self.blob_order.as_ref().clone()
    }

    pub fn cache_entry_id(&self) -> Option<&str> {
        self.cache_entry_id.as_deref()
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn last_refresh_at(&self) -> Option<Instant> {
        self.last_refresh_at
    }

    pub fn touch_refresh(&mut self) {
        self.last_refresh_at = Some(Instant::now());
    }

    pub fn entries_snapshot(&self) -> Arc<HashMap<String, BlobDescriptor>> {
        self.entries.clone()
    }

    fn normalize_blob_order(
        entries: &HashMap<String, BlobDescriptor>,
        requested_order: Vec<BlobDescriptor>,
    ) -> Vec<BlobDescriptor> {
        let mut by_digest = BTreeMap::new();
        for blob in entries.values() {
            by_digest
                .entry(blob.digest.clone())
                .or_insert(blob.size_bytes);
        }

        let mut ordered = Vec::with_capacity(by_digest.len());
        let mut seen = HashSet::new();
        for blob in requested_order {
            let digest = blob.digest.clone();
            let Some(size_bytes) = by_digest.get(&digest) else {
                continue;
            };
            if seen.insert(digest.clone()) {
                ordered.push(BlobDescriptor {
                    digest,
                    size_bytes: *size_bytes,
                });
            }
        }

        for (digest, size_bytes) in by_digest {
            if seen.insert(digest.clone()) {
                ordered.push(BlobDescriptor { digest, size_bytes });
            }
        }

        ordered
    }
}

pub fn ref_tag(name: &str, reference: &str) -> String {
    ref_tag_for_input(&format!("{}:{}", name, reference))
}

pub fn ref_tag_for_input(input: &str) -> String {
    format!("oci_ref_{}", sha256_hex(input.as_bytes()))
}

pub fn digest_tag(digest: &str) -> String {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    format!("oci_digest_{}", hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ref_tag_is_deterministic() {
        let tag1 = ref_tag("my-cache", "main");
        let tag2 = ref_tag("my-cache", "main");
        assert_eq!(tag1, tag2);
        assert!(tag1.starts_with("oci_ref_"));
        assert_eq!(tag1.len(), 8 + 64);
    }

    #[test]
    fn ref_tag_differs_for_different_inputs() {
        let tag1 = ref_tag("my-cache", "main");
        let tag2 = ref_tag("my-cache", "dev");
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn digest_tag_strips_prefix() {
        let tag = digest_tag("sha256:abc123def456");
        assert_eq!(tag, "oci_digest_abc123def456");
    }

    #[test]
    fn digest_tag_handles_bare_hex() {
        let tag = digest_tag("abc123def456");
        assert_eq!(tag, "oci_digest_abc123def456");
    }

    #[test]
    fn blob_locator_cache_insert_and_get() {
        let mut cache = BlobLocatorCache::default();
        cache.insert(
            "myimg",
            "sha256:abc",
            BlobLocatorEntry {
                cache_entry_id: "entry1".into(),
                size_bytes: 100,
                download_url: None,
                download_url_cached_at: None,
            },
        );
        let entry = cache.get("myimg", "sha256:abc").unwrap();
        assert_eq!(entry.cache_entry_id, "entry1");
        assert_eq!(entry.size_bytes, 100);
        assert!(cache.get("myimg", "sha256:xyz").is_none());
        assert!(cache.get("other", "sha256:abc").is_none());
    }

    #[test]
    fn find_by_digest_prefers_non_empty_finalized_session() {
        let now = Instant::now();
        let mut store = UploadSessionStore::default();

        store.create(UploadSession {
            id: "empty".to_string(),
            name: "img".to_string(),
            temp_path: PathBuf::from("/tmp/empty"),
            write_lock: Arc::new(Mutex::new(())),
            bytes_received: 0,
            finalized_digest: Some("sha256:abc".to_string()),
            finalized_size: Some(0),
            created_at: now,
        });

        store.create(UploadSession {
            id: "filled".to_string(),
            name: "img".to_string(),
            temp_path: PathBuf::from("/tmp/filled"),
            write_lock: Arc::new(Mutex::new(())),
            bytes_received: 0,
            finalized_digest: Some("sha256:abc".to_string()),
            finalized_size: Some(128),
            created_at: now,
        });

        let selected = store.find_by_digest("sha256:abc").expect("digest session");
        assert_eq!(selected.id, "filled");
        assert_eq!(selected.finalized_size, Some(128));
    }

    #[tokio::test]
    async fn blob_read_cache_insert_and_get_round_trip() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let cache = BlobReadCache::new_at(temp_dir.path().join("blob-cache"), 1024 * 1024)
            .expect("blob cache");
        let digest = format!("sha256:{}", "a".repeat(64));

        let inserted = cache.insert(&digest, b"hello-world").await.expect("insert");
        assert!(inserted);

        let handle = cache.get_handle(&digest).await.expect("cache hit");
        let mut file = tokio::fs::File::open(handle.path())
            .await
            .expect("open cached bytes");
        if handle.offset() > 0 {
            use tokio::io::AsyncSeekExt;
            file.seek(std::io::SeekFrom::Start(handle.offset()))
                .await
                .expect("seek cached bytes");
        }
        use tokio::io::AsyncReadExt;
        let mut bytes = vec![0u8; handle.size_bytes() as usize];
        file.read_exact(&mut bytes)
            .await
            .expect("read cached bytes");
        assert_eq!(bytes, b"hello-world");
    }

    #[tokio::test]
    async fn blob_read_cache_concurrent_insert_round_trip_integrity() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let cache = Arc::new(
            BlobReadCache::new_at(temp_dir.path().join("blob-cache"), 16 * 1024 * 1024)
                .expect("blob cache"),
        );

        let mut tasks = Vec::new();
        for idx in 0..64u64 {
            let cache = Arc::clone(&cache);
            tasks.push(tokio::spawn(async move {
                let digest = format!("sha256:{:064x}", idx + 1);
                let payload = format!("blob-{idx}-{}", "x".repeat(1024)).into_bytes();
                let inserted = cache.insert(&digest, &payload).await.expect("insert");
                assert!(inserted);
                (digest, payload)
            }));
        }

        let mut expected = Vec::new();
        for task in tasks {
            expected.push(task.await.expect("task"));
        }

        for (digest, payload) in expected {
            let handle = cache.get_handle(&digest).await.expect("cache hit");
            let mut file = tokio::fs::File::open(handle.path())
                .await
                .expect("open cached bytes");
            if handle.offset() > 0 {
                use tokio::io::AsyncSeekExt;
                file.seek(std::io::SeekFrom::Start(handle.offset()))
                    .await
                    .expect("seek cached bytes");
            }
            use tokio::io::AsyncReadExt;
            let mut bytes = vec![0u8; handle.size_bytes() as usize];
            file.read_exact(&mut bytes)
                .await
                .expect("read cached bytes");
            assert_eq!(bytes, payload);
        }
    }

    #[tokio::test]
    async fn blob_read_cache_concurrent_promote_round_trip_integrity() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let cache = Arc::new(
            BlobReadCache::new_at(temp_dir.path().join("blob-cache"), 16 * 1024 * 1024)
                .expect("blob cache"),
        );

        let mut tasks = Vec::new();
        for idx in 0..64u64 {
            let cache = Arc::clone(&cache);
            let source_path = temp_dir.path().join(format!("source-{idx}"));
            let payload = format!("promote-{idx}-{}", "y".repeat(1024)).into_bytes();
            tokio::fs::write(&source_path, &payload)
                .await
                .expect("source write");
            tasks.push(tokio::spawn(async move {
                let digest = format!("sha256:{:064x}", idx + 1000);
                let promoted = cache
                    .promote(&digest, &source_path, payload.len() as u64)
                    .await
                    .expect("promote");
                assert!(promoted);
                (digest, payload)
            }));
        }

        let mut expected = Vec::new();
        for task in tasks {
            expected.push(task.await.expect("task"));
        }

        for (digest, payload) in expected {
            let handle = cache.get_handle(&digest).await.expect("cache hit");
            let mut file = tokio::fs::File::open(handle.path())
                .await
                .expect("open cached bytes");
            if handle.offset() > 0 {
                use tokio::io::AsyncSeekExt;
                file.seek(std::io::SeekFrom::Start(handle.offset()))
                    .await
                    .expect("seek cached bytes");
            }
            use tokio::io::AsyncReadExt;
            let mut bytes = vec![0u8; handle.size_bytes() as usize];
            file.read_exact(&mut bytes)
                .await
                .expect("read cached bytes");
            assert_eq!(bytes, payload);
        }
    }

    #[tokio::test]
    async fn blob_read_cache_promote_moves_source_file() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let cache = BlobReadCache::new_at(temp_dir.path().join("blob-cache"), 1024 * 1024)
            .expect("blob cache");
        let digest = format!("sha256:{}", "b".repeat(64));
        let source_path = temp_dir.path().join("source-blob");
        tokio::fs::write(&source_path, b"promoted")
            .await
            .expect("source");

        let promoted = cache
            .promote(&digest, &source_path, 8)
            .await
            .expect("promote");
        assert!(promoted);
        assert!(!source_path.exists());
        assert!(cache.get_handle(&digest).await.is_some());
    }

    #[tokio::test]
    async fn blob_read_cache_rejects_invalid_digest() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let cache = BlobReadCache::new_at(temp_dir.path().join("blob-cache"), 1024 * 1024)
            .expect("blob cache");

        let inserted = cache
            .insert("not-a-digest", b"invalid")
            .await
            .expect("insert call");
        assert!(!inserted);
        assert!(cache.get_handle("not-a-digest").await.is_none());
    }

    #[test]
    fn kv_published_index_set_empty_incomplete_forces_refresh() {
        let mut index = KvPublishedIndex::default();
        let mut entries = HashMap::new();
        entries.insert(
            "ac/key".to_string(),
            BlobDescriptor {
                digest: format!("sha256:{}", "a".repeat(64)),
                size_bytes: 1,
            },
        );
        index.update(
            entries.clone(),
            entries.into_values().collect(),
            "cache-entry".to_string(),
        );
        assert!(index.is_complete());
        assert!(index.last_refresh_at().is_some());

        index.set_empty_incomplete();
        assert_eq!(index.entry_count(), 0);
        assert!(index.cache_entry_id().is_none());
        assert!(!index.is_complete());
        assert!(index.last_refresh_at().is_none());
    }

    #[tokio::test]
    async fn blob_read_cache_follower_timeout_clears_stale_inflight_entry() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let cache = BlobReadCache::new_at(temp_dir.path().join("blob-cache"), 1024 * 1024)
            .expect("blob cache");
        let digest = format!("sha256:{}", "c".repeat(64));
        let key = BlobReadCache::normalize_digest_hex(&digest).expect("normalized digest");

        {
            cache.inflight.insert(key.clone(), Arc::new(Notify::new()));
        }

        let inserted = cache
            .insert(&digest, b"stale-flight")
            .await
            .expect("insert");
        assert!(!inserted);
        assert!(!cache.inflight.contains_key(&key));

        let inserted_after_cleanup = cache
            .insert(&digest, b"stale-flight")
            .await
            .expect("insert after cleanup");
        assert!(inserted_after_cleanup);
    }
}
