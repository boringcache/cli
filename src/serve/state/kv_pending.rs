use super::*;

const DEFAULT_MAX_SPOOL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_SPOOL_BYTES_ENV: &str = "BORINGCACHE_MAX_SPOOL_BYTES";

pub fn max_spool_bytes() -> u64 {
    std::env::var(MAX_SPOOL_BYTES_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(DEFAULT_MAX_SPOOL_BYTES)
}

const DEFAULT_FLUSH_BLOB_THRESHOLD: usize = 2_000;
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
        if remove && let Some(bref) = self.blob_refs.remove(digest) {
            self.total_spool_bytes = self.total_spool_bytes.saturating_sub(bref.size_bytes);
            return Some(bref.path);
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
