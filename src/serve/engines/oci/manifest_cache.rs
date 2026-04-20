use std::time::{Duration, Instant};

use crate::api::models::cache::BlobDescriptor;

pub(crate) const OCI_MANIFEST_CACHE_TTL: Duration = Duration::from_secs(60);

pub struct OciManifestCacheEntry {
    pub index_json: Vec<u8>,
    pub content_type: String,
    pub manifest_digest: String,
    pub cache_entry_id: String,
    pub blobs: Vec<BlobDescriptor>,
    pub name: String,
    pub inserted_at: Instant,
}
