use crate::api::client::ApiClient;
use crate::api::models::cache::BlobDescriptor;
use crate::cas_oci::sha256_hex;
use crate::tag_utils::TagResolver;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};

#[derive(Clone)]
pub struct AppState {
    pub api_client: ApiClient,
    pub workspace: String,
    pub tag_resolver: TagResolver,
    pub configured_human_tags: Vec<String>,
    pub registry_root_tag: String,
    pub blob_locator: Arc<RwLock<BlobLocatorCache>>,
    pub upload_sessions: Arc<RwLock<UploadSessionStore>>,
    pub kv_pending: Arc<RwLock<KvPendingStore>>,
    pub kv_flush_lock: Arc<Mutex<()>>,
    pub kv_last_put: Arc<RwLock<Option<Instant>>>,
    pub kv_published_index: Arc<RwLock<KvPublishedIndex>>,
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
            if old.digest != blob.digest {
                self.dec_ref(&old.digest.clone());
            }
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
        for (key, blob) in &entries {
            self.entries.entry(key.clone()).or_insert(blob.clone());
        }
        for (digest, path) in blob_paths {
            self.blob_refs.entry(digest.clone()).or_insert_with(|| {
                let size = entries
                    .values()
                    .find(|b| b.digest == digest)
                    .map(|b| b.size_bytes)
                    .unwrap_or(0);
                self.total_spool_bytes += size;
                BlobRef {
                    path,
                    size_bytes: size,
                    refcount: 1,
                }
            });
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
    entries: HashMap<String, BlobDescriptor>,
    cache_entry_id: Option<String>,
    download_urls: HashMap<String, CachedUrl>,
}

impl KvPublishedIndex {
    pub fn update(&mut self, entries: HashMap<String, BlobDescriptor>, cache_entry_id: String) {
        self.entries = entries;
        self.cache_entry_id = Some(cache_entry_id);
        self.download_urls.clear();
    }

    pub fn set_download_urls(&mut self, urls: HashMap<String, String>) {
        let expires_at = Instant::now() + DOWNLOAD_URL_TTL;
        self.download_urls = urls
            .into_iter()
            .map(|(digest, url)| (digest, CachedUrl { url, expires_at }))
            .collect();
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
            bytes_received: 0,
            finalized_digest: Some("sha256:abc".to_string()),
            finalized_size: Some(0),
            created_at: now,
        });

        store.create(UploadSession {
            id: "filled".to_string(),
            name: "img".to_string(),
            temp_path: PathBuf::from("/tmp/filled"),
            bytes_received: 0,
            finalized_digest: Some("sha256:abc".to_string()),
            finalized_size: Some(128),
            created_at: now,
        });

        let selected = store.find_by_digest("sha256:abc").expect("digest session");
        assert_eq!(selected.id, "filled");
        assert_eq!(selected.finalized_size, Some(128));
    }
}
