use crate::api::client::ApiClient;
use crate::api::models::cache::BlobDescriptor;
use crate::cas_oci::sha256_hex;
use crate::tag_utils::TagResolver;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, Notify, RwLock};

#[derive(Clone)]
pub struct AppState {
    pub api_client: ApiClient,
    pub workspace: String,
    pub tag_resolver: TagResolver,
    pub configured_human_tags: Vec<String>,
    pub registry_root_tag: String,
    pub fail_on_cache_error: bool,
    pub blob_locator: Arc<RwLock<BlobLocatorCache>>,
    pub upload_sessions: Arc<RwLock<UploadSessionStore>>,
    pub kv_pending: Arc<RwLock<KvPendingStore>>,
    pub kv_flush_lock: Arc<Mutex<()>>,
    pub kv_lookup_inflight: Arc<std::sync::Mutex<HashMap<String, Arc<Notify>>>>,
    pub kv_last_put: Arc<AtomicU64>,
    pub kv_next_flush_at: Arc<RwLock<Option<Instant>>>,
    pub kv_flush_scheduled: Arc<AtomicBool>,
    pub kv_published_index: Arc<RwLock<KvPublishedIndex>>,
    pub kv_recent_misses: Arc<RwLock<HashMap<String, Instant>>>,
    pub blob_read_cache: Arc<BlobReadCache>,
}

pub const DEFAULT_BLOB_READ_CACHE_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const BLOB_READ_CACHE_DIR_NAME: &str = "boringcache-blob-cache";

struct BlobReadInFlightGuard {
    key: String,
    notify: Arc<Notify>,
    inflight: Arc<std::sync::Mutex<HashMap<String, Arc<Notify>>>>,
}

impl Drop for BlobReadInFlightGuard {
    fn drop(&mut self) {
        let mut inflight = self
            .inflight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inflight.remove(&self.key);
        self.notify.notify_waiters();
    }
}

enum BlobReadInFlight {
    Leader(BlobReadInFlightGuard),
    Follower(Arc<Notify>),
}

pub struct BlobReadCache {
    cache_dir: PathBuf,
    total_bytes: AtomicU64,
    max_bytes: u64,
    inflight: Arc<std::sync::Mutex<HashMap<String, Arc<Notify>>>>,
    evict_lock: Arc<Mutex<()>>,
}

impl BlobReadCache {
    pub fn new(max_bytes: u64) -> io::Result<Self> {
        let cache_dir = std::env::temp_dir().join(BLOB_READ_CACHE_DIR_NAME);
        Self::new_at(cache_dir, max_bytes)
    }

    pub fn new_at(cache_dir: PathBuf, max_bytes: u64) -> io::Result<Self> {
        std::fs::create_dir_all(&cache_dir)?;
        let total_bytes = Self::scan_total_bytes(&cache_dir)?;
        Ok(Self {
            cache_dir,
            total_bytes: AtomicU64::new(total_bytes),
            max_bytes: max_bytes.max(1),
            inflight: Arc::new(std::sync::Mutex::new(HashMap::new())),
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

    pub async fn get(&self, digest: &str) -> Option<PathBuf> {
        let path = self.path_for_digest(digest)?;
        match tokio::fs::metadata(&path).await {
            Ok(metadata) if metadata.is_file() && metadata.len() > 0 => Some(path),
            Ok(metadata) if metadata.is_file() => {
                let _ = tokio::fs::remove_file(&path).await;
                self.sub_total(metadata.len());
                None
            }
            Ok(_) => None,
            Err(_) => None,
        }
    }

    pub async fn remove(&self, digest: &str) {
        let Some(path) = self.path_for_digest(digest) else {
            return;
        };
        if let Ok(metadata) = tokio::fs::metadata(&path).await {
            if metadata.is_file() {
                let _ = tokio::fs::remove_file(&path).await;
                self.sub_total(metadata.len());
            }
        }
    }

    pub async fn insert(&self, digest: &str, data: &[u8]) -> io::Result<bool> {
        if data.is_empty() {
            return Ok(false);
        }
        let Some((path, key)) = self.path_and_key_for_digest(digest) else {
            return Ok(false);
        };

        if Self::is_non_empty_file(&path).await? {
            return Ok(false);
        }

        match self.begin_inflight(key) {
            BlobReadInFlight::Follower(notify) => {
                notify.notified().await;
                Ok(false)
            }
            BlobReadInFlight::Leader(_guard) => {
                if Self::is_non_empty_file(&path).await? {
                    return Ok(false);
                }

                tokio::fs::create_dir_all(&self.cache_dir).await?;
                let temp_path = self.temp_path(&path);
                let mut temp_file = tokio::fs::File::create(&temp_path).await?;
                tokio::io::AsyncWriteExt::write_all(&mut temp_file, data).await?;
                tokio::io::AsyncWriteExt::flush(&mut temp_file).await?;
                temp_file.sync_all().await?;
                drop(temp_file);

                match tokio::fs::rename(&temp_path, &path).await {
                    Ok(_) => {
                        self.total_bytes
                            .fetch_add(data.len() as u64, Ordering::AcqRel);
                        if let Err(error) = self.evict_over_budget().await {
                            log::warn!("Blob read cache eviction failed after insert: {error}");
                        }
                        Ok(true)
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        let _ = tokio::fs::remove_file(&temp_path).await;
                        Ok(false)
                    }
                    Err(error) => {
                        let _ = tokio::fs::remove_file(&temp_path).await;
                        Err(error)
                    }
                }
            }
        }
    }

    pub async fn promote(
        &self,
        digest: &str,
        src_path: &Path,
        size_bytes: u64,
    ) -> io::Result<bool> {
        let Some((dst_path, key)) = self.path_and_key_for_digest(digest) else {
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

        if Self::is_non_empty_file(&dst_path).await? {
            let _ = tokio::fs::remove_file(src_path).await;
            return Ok(false);
        }

        match self.begin_inflight(key) {
            BlobReadInFlight::Follower(notify) => {
                notify.notified().await;
                let _ = tokio::fs::remove_file(src_path).await;
                Ok(false)
            }
            BlobReadInFlight::Leader(_guard) => {
                if Self::is_non_empty_file(&dst_path).await? {
                    let _ = tokio::fs::remove_file(src_path).await;
                    return Ok(false);
                }

                tokio::fs::create_dir_all(&self.cache_dir).await?;
                match tokio::fs::rename(src_path, &dst_path).await {
                    Ok(_) => {
                        self.total_bytes.fetch_add(source_size, Ordering::AcqRel);
                        if let Err(error) = self.evict_over_budget().await {
                            log::warn!("Blob read cache eviction failed after promote: {error}");
                        }
                        Ok(true)
                    }
                    Err(error)
                        if error.kind() == io::ErrorKind::CrossesDevices
                            || error.raw_os_error() == Some(18) =>
                    {
                        let temp_path = self.temp_path(&dst_path);
                        tokio::fs::copy(src_path, &temp_path).await?;
                        match tokio::fs::rename(&temp_path, &dst_path).await {
                            Ok(_) => {
                                let _ = tokio::fs::remove_file(src_path).await;
                                self.total_bytes.fetch_add(source_size, Ordering::AcqRel);
                                if let Err(error) = self.evict_over_budget().await {
                                    log::warn!(
                                        "Blob read cache eviction failed after cross-device promote: {error}"
                                    );
                                }
                                Ok(true)
                            }
                            Err(rename_error)
                                if rename_error.kind() == io::ErrorKind::AlreadyExists =>
                            {
                                let _ = tokio::fs::remove_file(&temp_path).await;
                                let _ = tokio::fs::remove_file(src_path).await;
                                Ok(false)
                            }
                            Err(rename_error) => {
                                let _ = tokio::fs::remove_file(&temp_path).await;
                                Err(rename_error)
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        let _ = tokio::fs::remove_file(src_path).await;
                        Ok(false)
                    }
                    Err(error) => Err(error),
                }
            }
        }
    }

    async fn evict_over_budget(&self) -> io::Result<()> {
        if self.total_bytes.load(Ordering::Acquire) <= self.max_bytes {
            return Ok(());
        }

        let _guard = self.evict_lock.lock().await;

        let mut read_dir = tokio::fs::read_dir(&self.cache_dir).await?;
        let mut files: Vec<(std::time::SystemTime, PathBuf, u64)> = Vec::new();
        let mut total = 0u64;

        while let Some(entry) = read_dir.next_entry().await? {
            let path = entry.path();
            let metadata = match entry.metadata().await {
                Ok(metadata) if metadata.is_file() => metadata,
                Ok(_) => continue,
                Err(_) => continue,
            };
            let modified = metadata
                .modified()
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            total = total.saturating_add(metadata.len());
            files.push((modified, path, metadata.len()));
        }

        if total <= self.max_bytes {
            self.total_bytes.store(total, Ordering::Release);
            return Ok(());
        }

        files.sort_by_key(|(modified, _, _)| *modified);
        for (_, path, size) in files {
            if total <= self.max_bytes {
                break;
            }
            if tokio::fs::remove_file(&path).await.is_ok() {
                total = total.saturating_sub(size);
            }
        }

        self.total_bytes.store(total, Ordering::Release);
        Ok(())
    }

    fn scan_total_bytes(cache_dir: &Path) -> io::Result<u64> {
        let mut total_bytes = 0u64;
        for entry in std::fs::read_dir(cache_dir)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.is_file() {
                total_bytes = total_bytes.saturating_add(metadata.len());
            }
        }
        Ok(total_bytes)
    }

    fn temp_path(&self, dst_path: &Path) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let suffix = COUNTER.fetch_add(1, Ordering::Relaxed);
        let file_name = dst_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("blob");
        self.cache_dir.join(format!(".tmp-{file_name}-{suffix}"))
    }

    fn begin_inflight(&self, key: String) -> BlobReadInFlight {
        let mut inflight = self
            .inflight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = inflight.get(&key) {
            return BlobReadInFlight::Follower(existing.clone());
        }

        let notify = Arc::new(Notify::new());
        inflight.insert(key.clone(), notify.clone());
        BlobReadInFlight::Leader(BlobReadInFlightGuard {
            key,
            notify,
            inflight: self.inflight.clone(),
        })
    }

    fn path_and_key_for_digest(&self, digest: &str) -> Option<(PathBuf, String)> {
        let key = Self::normalize_digest_hex(digest)?;
        Some((self.cache_dir.join(&key), key))
    }

    fn path_for_digest(&self, digest: &str) -> Option<PathBuf> {
        self.path_and_key_for_digest(digest).map(|(path, _)| path)
    }

    fn normalize_digest_hex(digest: &str) -> Option<String> {
        let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        Some(hex.to_ascii_lowercase())
    }

    async fn is_non_empty_file(path: &Path) -> io::Result<bool> {
        match tokio::fs::metadata(path).await {
            Ok(metadata) if metadata.is_file() && metadata.len() > 0 => Ok(true),
            Ok(metadata) if metadata.is_file() => {
                let _ = tokio::fs::remove_file(path).await;
                Ok(false)
            }
            Ok(_) => Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
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

pub const MAX_SPOOL_BYTES: u64 = 512 * 1024 * 1024;
pub const FLUSH_BLOB_THRESHOLD: usize = 500;
pub const FLUSH_SIZE_THRESHOLD: u64 = 256 * 1024 * 1024;

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
}

struct BlobRef {
    path: PathBuf,
    size_bytes: u64,
    refcount: u32,
}

impl KvPendingStore {
    pub fn insert(
        &mut self,
        scoped_key: String,
        blob: BlobDescriptor,
        temp_path: PathBuf,
    ) -> Option<PathBuf> {
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
                if self.total_spool_bytes + blob.size_bytes > MAX_SPOOL_BYTES {
                    log::warn!(
                        "KV spool budget exceeded ({} + {} > {}), dropping oldest",
                        self.total_spool_bytes,
                        blob.size_bytes,
                        MAX_SPOOL_BYTES
                    );
                }
                self.total_spool_bytes += blob.size_bytes;
                self.blob_refs.insert(
                    blob.digest.clone(),
                    BlobRef {
                        path: temp_path,
                        size_bytes: blob.size_bytes,
                        refcount: 1,
                    },
                );
                None
            }
        };

        self.entries.insert(scoped_key, blob);
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

    pub fn take_all(&mut self) -> (BTreeMap<String, BlobDescriptor>, HashMap<String, PathBuf>) {
        let entries = std::mem::take(&mut self.entries);
        let blob_paths: HashMap<String, PathBuf> = self
            .blob_refs
            .drain()
            .map(|(digest, bref)| (digest, bref.path))
            .collect();
        self.total_spool_bytes = 0;
        (entries, blob_paths)
    }

    pub fn restore(
        &mut self,
        entries: BTreeMap<String, BlobDescriptor>,
        blob_paths: HashMap<String, PathBuf>,
    ) {
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
                        let _ = std::fs::remove_file(path);
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
                            },
                        );
                    }
                }
            }
        }

        for (digest, path) in &blob_paths {
            if !restore_refcounts.contains_key(digest) {
                let _ = std::fs::remove_file(path);
            }
        }
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

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
    cache_entry_id: Option<String>,
    download_urls: HashMap<String, CachedUrl>,
    complete: bool,
    last_refresh_at: Option<Instant>,
}

impl KvPublishedIndex {
    pub fn update(&mut self, entries: HashMap<String, BlobDescriptor>, cache_entry_id: String) {
        let now = Instant::now();
        let cache_entry_changed = self.cache_entry_id.as_deref() != Some(cache_entry_id.as_str());
        let active_digests: HashSet<String> =
            entries.values().map(|blob| blob.digest.clone()).collect();
        self.entries = Arc::new(entries);
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
        }

        let entries = Arc::make_mut(&mut self.entries);
        entries.insert(scoped_key, blob);
        self.complete = false;
        self.last_refresh_at = Some(Instant::now());
    }

    pub fn set_empty(&mut self) {
        self.entries = Arc::new(HashMap::new());
        self.cache_entry_id = None;
        self.download_urls.clear();
        self.complete = true;
        self.last_refresh_at = Some(Instant::now());
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

    pub fn invalidate_download_url(&mut self, digest: &str) {
        self.download_urls.remove(digest);
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
        let mut seen = HashMap::new();
        for blob in self.entries.values() {
            seen.entry(blob.digest.clone()).or_insert(BlobDescriptor {
                digest: blob.digest.clone(),
                size_bytes: blob.size_bytes,
            });
        }
        seen.into_values().collect()
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

        let path = cache.get(&digest).await.expect("cache hit");
        let bytes = tokio::fs::read(path).await.expect("read cached bytes");
        assert_eq!(bytes, b"hello-world");
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
        assert!(cache.get(&digest).await.is_some());
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
        assert!(cache.get("not-a-digest").await.is_none());
    }
}
