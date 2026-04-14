use super::*;

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
        self.download_urls.clear();
        self.merge_download_urls(urls);
    }

    pub fn merge_download_urls(&mut self, urls: HashMap<String, String>) {
        let expires_at = Instant::now() + DOWNLOAD_URL_TTL;
        for (digest, url) in urls {
            self.download_urls
                .insert(digest, CachedUrl { url, expires_at });
        }
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
