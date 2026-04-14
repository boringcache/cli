use super::*;

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
