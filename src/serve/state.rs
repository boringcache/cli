use crate::api::client::ApiClient;
use crate::cas_oci::sha256_hex;
use crate::tag_utils::TagResolver;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AppState {
    pub api_client: ApiClient,
    pub workspace: String,
    pub tag_resolver: TagResolver,
    pub blob_locator: Arc<RwLock<BlobLocatorCache>>,
    pub upload_sessions: Arc<RwLock<UploadSessionStore>>,
}

#[derive(Debug, Clone)]
pub struct BlobLocatorEntry {
    pub cache_entry_id: String,
    pub size_bytes: u64,
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
            .find(|s| s.finalized_digest.as_deref() == Some(digest))
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
            },
        );
        let entry = cache.get("myimg", "sha256:abc").unwrap();
        assert_eq!(entry.cache_entry_id, "entry1");
        assert_eq!(entry.size_bytes, 100);
        assert!(cache.get("myimg", "sha256:xyz").is_none());
        assert!(cache.get("other", "sha256:abc").is_none());
    }
}
