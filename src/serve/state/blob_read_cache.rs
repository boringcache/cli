use super::*;

const BLOB_READ_CACHE_DIR_ENV: &str = "BORINGCACHE_BLOB_READ_CACHE_DIR";
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

    pub fn from_file_range(path: PathBuf, offset: u64, size_bytes: u64) -> Self {
        Self {
            path,
            offset,
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

#[derive(Debug)]
pub struct BlobReadLease {
    key: String,
    handle: BlobReadHandle,
    pins: Arc<DashMap<String, AtomicU64>>,
}

impl BlobReadLease {
    pub fn handle(&self) -> &BlobReadHandle {
        &self.handle
    }

    pub fn path(&self) -> &Path {
        self.handle.path()
    }

    pub fn offset(&self) -> u64 {
        self.handle.offset()
    }

    pub fn size_bytes(&self) -> u64 {
        self.handle.size_bytes()
    }
}

impl Drop for BlobReadLease {
    fn drop(&mut self) {
        BlobReadCache::decrement_pin(&self.pins, &self.key);
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
    pub(super) inflight: Arc<DashMap<String, Arc<Notify>>>,
    storage_index: Arc<DashMap<String, BlobReadStorageEntry>>,
    pins: Arc<DashMap<String, AtomicU64>>,
    segment_entry_keys: Arc<DashMap<u64, Vec<String>>>,
    segment_state: Arc<Mutex<BlobReadSegmentState>>,
    append_lock: Arc<Mutex<()>>,
    evict_lock: Arc<Mutex<()>>,
}

impl BlobReadCache {
    pub fn new(max_bytes: u64) -> io::Result<Self> {
        let cache_dir = std::env::var_os(BLOB_READ_CACHE_DIR_ENV)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join(BLOB_READ_CACHE_DIR_NAME));
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
            pins: Arc::new(DashMap::new()),
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
                if !metadata.is_file() {
                    self.storage_index.remove(&key);
                    return None;
                }
                if metadata.len() == 0 && size_bytes > 0 {
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
            } => Some(BlobReadHandle {
                path,
                offset,
                size_bytes,
            }),
        }
    }

    pub async fn get(&self, digest: &str) -> Option<PathBuf> {
        let handle = self.get_handle(digest).await?;
        if handle.offset == 0 {
            return Some(handle.path);
        }
        None
    }

    pub async fn lease_handle(&self, digest: &str) -> Option<BlobReadLease> {
        let key = Self::normalize_digest_hex(digest)?;
        {
            let pin = self
                .pins
                .entry(key.clone())
                .or_insert_with(|| AtomicU64::new(0));
            pin.fetch_add(1, Ordering::AcqRel);
        }

        let Some(handle) = self.get_handle(&key).await else {
            Self::decrement_pin(&self.pins, &key);
            return None;
        };

        Some(BlobReadLease {
            key,
            handle,
            pins: Arc::clone(&self.pins),
        })
    }

    pub async fn remove(&self, digest: &str) {
        let Some(key) = Self::normalize_digest_hex(digest) else {
            return;
        };
        if self.is_pinned(&key) {
            return;
        }
        let Some((_, entry)) = self.storage_index.remove(&key) else {
            return;
        };
        if let BlobReadStorageEntry::LegacyFile { path, size_bytes } = entry {
            let _ = tokio::fs::remove_file(&path).await;
            self.sub_total(size_bytes);
        }
    }

    pub async fn insert(&self, digest: &str, data: &[u8]) -> io::Result<bool> {
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

                let entry = match self.promote_legacy_file(&key, src_path, source_size).await {
                    Ok(Some(entry)) => Some(entry),
                    Ok(None) => None,
                    Err(error) if is_cross_device_rename_error(&error) => {
                        self.append_blob_from_file(&key, src_path, source_size)
                            .await?
                    }
                    Err(error) => return Err(error),
                };
                let Some(entry) = entry else {
                    return Ok(false);
                };
                self.track_storage_entry(key, entry);
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

    async fn promote_legacy_file(
        &self,
        digest_hex: &str,
        src_path: &Path,
        size_bytes: u64,
    ) -> io::Result<Option<BlobReadStorageEntry>> {
        let dest_path = self.cache_dir.join(digest_hex);
        match tokio::fs::rename(src_path, &dest_path).await {
            Ok(()) => {
                self.total_bytes.fetch_add(size_bytes, Ordering::AcqRel);
                Ok(Some(BlobReadStorageEntry::LegacyFile {
                    path: dest_path,
                    size_bytes,
                }))
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let _ = tokio::fs::remove_file(src_path).await;
                Ok(None)
            }
            Err(error) => Err(error),
        }
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
            if self.is_pinned(&digest) {
                continue;
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
                if self.segment_has_pins(segment_id) {
                    continue;
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

    fn is_pinned(&self, key: &str) -> bool {
        self.pins
            .get(key)
            .is_some_and(|pin| pin.load(Ordering::Acquire) > 0)
    }

    fn segment_has_pins(&self, segment_id: u64) -> bool {
        self.segment_entry_keys
            .get(&segment_id)
            .is_some_and(|keys| keys.iter().any(|key| self.is_pinned(key)))
    }

    fn decrement_pin(pins: &DashMap<String, AtomicU64>, key: &str) {
        if let Some(pin) = pins.get(key) {
            pin.fetch_sub(1, Ordering::AcqRel);
        }
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

    pub(super) fn normalize_digest_hex(digest: &str) -> Option<String> {
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

fn is_cross_device_rename_error(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(18)
    }

    #[cfg(not(unix))]
    {
        let _ = error;
        false
    }
}
