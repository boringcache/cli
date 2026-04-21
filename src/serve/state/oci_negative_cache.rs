use super::*;

const BLOB_LOCATOR_MISS_TTL: std::time::Duration = std::time::Duration::from_secs(5);
const MANIFEST_MISS_TTL: std::time::Duration = std::time::Duration::from_secs(5);
const REMOTE_BLOB_MISS_TTL: std::time::Duration = std::time::Duration::from_secs(5);
const DOWNLOAD_URL_MISS_TTL: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OciNegativeCacheReason {
    ManifestRef,
    BlobLocator,
    DownloadUrl,
    RemoteBlob,
}

impl OciNegativeCacheReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ManifestRef => "manifest-ref",
            Self::BlobLocator => "blob-locator",
            Self::DownloadUrl => "download-url",
            Self::RemoteBlob => "remote-blob",
        }
    }

    fn ttl(self) -> std::time::Duration {
        match self {
            Self::ManifestRef => MANIFEST_MISS_TTL,
            Self::BlobLocator => BLOB_LOCATOR_MISS_TTL,
            Self::DownloadUrl => DOWNLOAD_URL_MISS_TTL,
            Self::RemoteBlob => REMOTE_BLOB_MISS_TTL,
        }
    }
}

#[derive(Clone)]
struct OciNegativeCacheEntry {
    reason: OciNegativeCacheReason,
    name: String,
    subject: String,
    expires_at: Instant,
}

pub struct OciNegativeCache {
    entries: DashMap<String, OciNegativeCacheEntry>,
    generation: AtomicU64,
}

impl OciNegativeCache {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            generation: AtomicU64::new(0),
        }
    }

    pub fn contains_manifest_ref_miss(
        &self,
        workspace: &str,
        registry_root_tag: &str,
        name: &str,
        reference: &str,
    ) -> bool {
        self.contains(
            workspace,
            registry_root_tag,
            OciNegativeCacheReason::ManifestRef,
            name,
            reference,
            None,
        )
    }

    pub fn insert_manifest_ref_miss(
        &self,
        workspace: &str,
        registry_root_tag: &str,
        name: &str,
        reference: &str,
    ) {
        self.insert(
            workspace,
            registry_root_tag,
            OciNegativeCacheReason::ManifestRef,
            name,
            reference,
            None,
        );
    }

    pub fn contains_blob_locator_miss(
        &self,
        workspace: &str,
        registry_root_tag: &str,
        name: &str,
        digest: &str,
    ) -> bool {
        self.contains(
            workspace,
            registry_root_tag,
            OciNegativeCacheReason::BlobLocator,
            name,
            digest,
            None,
        )
    }

    pub fn insert_blob_locator_miss(
        &self,
        workspace: &str,
        registry_root_tag: &str,
        name: &str,
        digest: &str,
    ) {
        self.insert(
            workspace,
            registry_root_tag,
            OciNegativeCacheReason::BlobLocator,
            name,
            digest,
            None,
        );
    }

    pub fn contains_download_url_miss(
        &self,
        workspace: &str,
        registry_root_tag: &str,
        name: &str,
        digest: &str,
        cache_entry_id: &str,
    ) -> bool {
        self.contains(
            workspace,
            registry_root_tag,
            OciNegativeCacheReason::DownloadUrl,
            name,
            digest,
            Some(cache_entry_id),
        )
    }

    pub fn insert_download_url_miss(
        &self,
        workspace: &str,
        registry_root_tag: &str,
        name: &str,
        digest: &str,
        cache_entry_id: &str,
    ) {
        self.insert(
            workspace,
            registry_root_tag,
            OciNegativeCacheReason::DownloadUrl,
            name,
            digest,
            Some(cache_entry_id),
        );
    }

    pub fn contains_remote_blob_miss(
        &self,
        workspace: &str,
        registry_root_tag: &str,
        name: &str,
        digest: &str,
    ) -> bool {
        self.contains(
            workspace,
            registry_root_tag,
            OciNegativeCacheReason::RemoteBlob,
            name,
            digest,
            None,
        )
    }

    pub fn insert_remote_blob_miss(
        &self,
        workspace: &str,
        registry_root_tag: &str,
        name: &str,
        digest: &str,
    ) {
        self.insert(
            workspace,
            registry_root_tag,
            OciNegativeCacheReason::RemoteBlob,
            name,
            digest,
            None,
        );
    }

    pub fn invalidate_blob(&self, name: &str, digest: &str) {
        let keys = self
            .entries
            .iter()
            .filter_map(|entry| {
                let value = entry.value();
                if value.name == name
                    && value.subject == digest
                    && matches!(
                        value.reason,
                        OciNegativeCacheReason::BlobLocator
                            | OciNegativeCacheReason::DownloadUrl
                            | OciNegativeCacheReason::RemoteBlob
                    )
                {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for key in keys {
            self.entries.remove(&key);
        }
    }

    pub fn invalidate_all(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.entries.clear();
    }

    pub fn metadata_hints(&self) -> BTreeMap<String, String> {
        self.prune_expired();
        let mut hints = BTreeMap::new();
        let mut manifest_refs = 0u64;
        let mut blob_locators = 0u64;
        let mut download_urls = 0u64;
        let mut remote_blobs = 0u64;
        for entry in &self.entries {
            match entry.reason {
                OciNegativeCacheReason::ManifestRef => {
                    manifest_refs = manifest_refs.saturating_add(1)
                }
                OciNegativeCacheReason::BlobLocator => {
                    blob_locators = blob_locators.saturating_add(1)
                }
                OciNegativeCacheReason::DownloadUrl => {
                    download_urls = download_urls.saturating_add(1)
                }
                OciNegativeCacheReason::RemoteBlob => remote_blobs = remote_blobs.saturating_add(1),
            }
        }
        insert_if_positive(
            &mut hints,
            "oci_negative_manifest_ref_entries",
            manifest_refs,
        );
        insert_if_positive(
            &mut hints,
            "oci_negative_blob_locator_entries",
            blob_locators,
        );
        insert_if_positive(
            &mut hints,
            "oci_negative_download_url_entries",
            download_urls,
        );
        insert_if_positive(&mut hints, "oci_negative_remote_blob_entries", remote_blobs);
        hints.insert(
            "oci_negative_generation".to_string(),
            self.generation.load(Ordering::Acquire).to_string(),
        );
        hints
    }

    fn contains(
        &self,
        workspace: &str,
        registry_root_tag: &str,
        reason: OciNegativeCacheReason,
        name: &str,
        subject: &str,
        cache_entry_id: Option<&str>,
    ) -> bool {
        let key = self.key(
            workspace,
            registry_root_tag,
            reason,
            name,
            subject,
            cache_entry_id,
        );
        let Some(entry) = self.entries.get(&key) else {
            return false;
        };
        if Instant::now() < entry.expires_at {
            return true;
        }
        drop(entry);
        self.entries.remove(&key);
        false
    }

    fn insert(
        &self,
        workspace: &str,
        registry_root_tag: &str,
        reason: OciNegativeCacheReason,
        name: &str,
        subject: &str,
        cache_entry_id: Option<&str>,
    ) {
        let key = self.key(
            workspace,
            registry_root_tag,
            reason,
            name,
            subject,
            cache_entry_id,
        );
        self.entries.insert(
            key,
            OciNegativeCacheEntry {
                reason,
                name: name.to_string(),
                subject: subject.to_string(),
                expires_at: Instant::now() + reason.ttl(),
            },
        );
    }

    fn key(
        &self,
        workspace: &str,
        registry_root_tag: &str,
        reason: OciNegativeCacheReason,
        name: &str,
        subject: &str,
        cache_entry_id: Option<&str>,
    ) -> String {
        format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}",
            self.generation.load(Ordering::Acquire),
            workspace,
            registry_root_tag,
            reason.as_str(),
            name,
            subject,
            cache_entry_id.unwrap_or("")
        )
    }

    fn prune_expired(&self) {
        let now = Instant::now();
        let keys = self
            .entries
            .iter()
            .filter_map(|entry| {
                if entry.expires_at <= now {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for key in keys {
            self.entries.remove(&key);
        }
    }
}

impl Default for OciNegativeCache {
    fn default() -> Self {
        Self::new()
    }
}

fn insert_if_positive(hints: &mut BTreeMap<String, String>, key: &str, value: u64) {
    if value > 0 {
        hints.insert(key.to_string(), value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_invalidation_removes_blob_miss_classes_only() {
        let cache = OciNegativeCache::new();
        cache.insert_blob_locator_miss("org/repo", "registry", "img", "sha256:abc");
        cache.insert_download_url_miss("org/repo", "registry", "img", "sha256:abc", "entry-1");
        cache.insert_remote_blob_miss("org/repo", "registry", "img", "sha256:abc");
        cache.insert_manifest_ref_miss("org/repo", "registry", "img", "latest");

        assert!(cache.contains_blob_locator_miss("org/repo", "registry", "img", "sha256:abc"));
        assert!(cache.contains_download_url_miss(
            "org/repo",
            "registry",
            "img",
            "sha256:abc",
            "entry-1"
        ));
        assert!(cache.contains_remote_blob_miss("org/repo", "registry", "img", "sha256:abc"));

        cache.invalidate_blob("img", "sha256:abc");

        assert!(!cache.contains_blob_locator_miss("org/repo", "registry", "img", "sha256:abc"));
        assert!(!cache.contains_download_url_miss(
            "org/repo",
            "registry",
            "img",
            "sha256:abc",
            "entry-1"
        ));
        assert!(!cache.contains_remote_blob_miss("org/repo", "registry", "img", "sha256:abc"));
        assert!(cache.contains_manifest_ref_miss("org/repo", "registry", "img", "latest"));
    }

    #[test]
    fn invalidate_all_bumps_generation_and_clears_entries() {
        let cache = OciNegativeCache::new();
        cache.insert_manifest_ref_miss("org/repo", "registry", "img", "latest");
        assert!(cache.contains_manifest_ref_miss("org/repo", "registry", "img", "latest"));

        cache.invalidate_all();

        assert!(!cache.contains_manifest_ref_miss("org/repo", "registry", "img", "latest"));
        assert_eq!(
            cache
                .metadata_hints()
                .get("oci_negative_generation")
                .map(String::as_str),
            Some("1")
        );
    }
}
