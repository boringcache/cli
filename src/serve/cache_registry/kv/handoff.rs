use super::*;
use serde::{Deserialize, Serialize};

pub(crate) const KV_PENDING_PUBLISH_HANDOFF_DIR: &str = "kv-pending-publish";
pub(crate) const KV_PENDING_PUBLISH_HANDOFF_VERSION: u32 = 2;
pub(crate) const KV_PENDING_PUBLISH_HANDOFF_MAX_AGE: std::time::Duration =
    std::time::Duration::from_secs(30 * 60);
pub(crate) const KV_PENDING_PUBLISH_HANDOFF_RECONCILE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(10 * 60);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KvPendingPublishHandoff {
    pub(crate) version: u32,
    pub(crate) persisted_at_unix_ms: u64,
    pub(crate) workspace: String,
    pub(crate) registry_root_tag: String,
    pub(crate) configured_human_tags: Vec<String>,
    pub(crate) cache_entry_id: String,
    pub(crate) entries: BTreeMap<String, BlobDescriptor>,
    pub(crate) blob_order: Vec<BlobDescriptor>,
    pub(crate) download_urls: HashMap<String, String>,
    pub(crate) root_pending: Option<PendingMetadata>,
    pub(crate) pending_alias_tags: bool,
    pub(crate) pending_blob_paths: HashMap<String, PathBuf>,
}

pub(crate) struct PendingPublishHandoffPersist<'a> {
    pub(crate) root_pending: Option<&'a PendingMetadata>,
    pub(crate) pending_alias_tags: bool,
    pub(crate) pending_blob_paths: Option<&'a HashMap<String, PathBuf>>,
}
