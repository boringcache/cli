use super::*;

pub struct BlobReadMetrics {
    local_count: AtomicU64,
    remote_count: AtomicU64,
    local_bytes: AtomicU64,
    remote_bytes: AtomicU64,
    local_duration_ms: AtomicU64,
    remote_duration_ms: AtomicU64,
}

impl BlobReadMetrics {
    pub fn new() -> Self {
        Self {
            local_count: AtomicU64::new(0),
            remote_count: AtomicU64::new(0),
            local_bytes: AtomicU64::new(0),
            remote_bytes: AtomicU64::new(0),
            local_duration_ms: AtomicU64::new(0),
            remote_duration_ms: AtomicU64::new(0),
        }
    }

    pub fn record_local(&self, bytes: u64, duration_ms: u64) {
        self.local_count.fetch_add(1, Ordering::AcqRel);
        self.local_bytes.fetch_add(bytes, Ordering::AcqRel);
        self.local_duration_ms
            .fetch_add(duration_ms, Ordering::AcqRel);
    }

    pub fn record_remote(&self, bytes: u64, duration_ms: u64) {
        self.remote_count.fetch_add(1, Ordering::AcqRel);
        self.remote_bytes.fetch_add(bytes, Ordering::AcqRel);
        self.remote_duration_ms
            .fetch_add(duration_ms, Ordering::AcqRel);
    }

    pub fn metadata_hints(&self) -> BTreeMap<String, String> {
        let local_count = self.local_count.load(Ordering::Acquire);
        let remote_count = self.remote_count.load(Ordering::Acquire);
        let total_count = local_count.saturating_add(remote_count);
        if total_count == 0 {
            return BTreeMap::new();
        }

        let local_bytes = self.local_bytes.load(Ordering::Acquire);
        let remote_bytes = self.remote_bytes.load(Ordering::Acquire);
        let local_duration_ms = self.local_duration_ms.load(Ordering::Acquire);
        let remote_duration_ms = self.remote_duration_ms.load(Ordering::Acquire);
        let local_hit_rate_pct = ((local_count as f64 / total_count as f64) * 100.0).round();
        let local_avg_ms = if local_count == 0 {
            0
        } else {
            local_duration_ms / local_count
        };
        let remote_avg_ms = if remote_count == 0 {
            0
        } else {
            remote_duration_ms / remote_count
        };

        BTreeMap::from([
            ("blob_read_local_count".to_string(), local_count.to_string()),
            (
                "blob_read_remote_count".to_string(),
                remote_count.to_string(),
            ),
            ("blob_read_local_bytes".to_string(), local_bytes.to_string()),
            (
                "blob_read_remote_bytes".to_string(),
                remote_bytes.to_string(),
            ),
            (
                "blob_read_local_hit_rate_pct".to_string(),
                local_hit_rate_pct.to_string(),
            ),
            (
                "blob_read_local_avg_ms".to_string(),
                local_avg_ms.to_string(),
            ),
            (
                "blob_read_remote_avg_ms".to_string(),
                remote_avg_ms.to_string(),
            ),
        ])
    }
}

impl Default for BlobReadMetrics {
    fn default() -> Self {
        Self::new()
    }
}

pub struct OciBodyMetrics {
    local_hits: AtomicU64,
    remote_fetches: AtomicU64,
    local_bytes: AtomicU64,
    remote_bytes: AtomicU64,
    local_duration_ms: AtomicU64,
    remote_duration_ms: AtomicU64,
}

impl OciBodyMetrics {
    pub fn new() -> Self {
        Self {
            local_hits: AtomicU64::new(0),
            remote_fetches: AtomicU64::new(0),
            local_bytes: AtomicU64::new(0),
            remote_bytes: AtomicU64::new(0),
            local_duration_ms: AtomicU64::new(0),
            remote_duration_ms: AtomicU64::new(0),
        }
    }

    pub fn record_local(&self, bytes: u64, duration_ms: u64) {
        self.local_hits.fetch_add(1, Ordering::AcqRel);
        self.local_bytes.fetch_add(bytes, Ordering::AcqRel);
        self.local_duration_ms
            .fetch_add(duration_ms, Ordering::AcqRel);
    }

    pub fn record_remote(&self, bytes: u64, duration_ms: u64) {
        self.remote_fetches.fetch_add(1, Ordering::AcqRel);
        self.remote_bytes.fetch_add(bytes, Ordering::AcqRel);
        self.remote_duration_ms
            .fetch_add(duration_ms, Ordering::AcqRel);
    }

    pub fn metadata_hints(&self) -> BTreeMap<String, String> {
        let local_hits = self.local_hits.load(Ordering::Acquire);
        let remote_fetches = self.remote_fetches.load(Ordering::Acquire);
        if local_hits == 0 && remote_fetches == 0 {
            return BTreeMap::new();
        }

        let local_bytes = self.local_bytes.load(Ordering::Acquire);
        let remote_bytes = self.remote_bytes.load(Ordering::Acquire);
        let local_duration_ms = self.local_duration_ms.load(Ordering::Acquire);
        let remote_duration_ms = self.remote_duration_ms.load(Ordering::Acquire);

        BTreeMap::from([
            ("oci_body_local_hits".to_string(), local_hits.to_string()),
            (
                "oci_body_remote_fetches".to_string(),
                remote_fetches.to_string(),
            ),
            ("oci_body_local_bytes".to_string(), local_bytes.to_string()),
            (
                "oci_body_remote_bytes".to_string(),
                remote_bytes.to_string(),
            ),
            (
                "oci_body_local_duration_ms".to_string(),
                local_duration_ms.to_string(),
            ),
            (
                "oci_body_remote_duration_ms".to_string(),
                remote_duration_ms.to_string(),
            ),
        ])
    }
}

impl Default for OciBodyMetrics {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SingleflightMetrics {
    kinds: DashMap<String, Arc<SingleflightKindMetrics>>,
}

struct SingleflightKindMetrics {
    leaders: AtomicU64,
    followers: AtomicU64,
    follower_timeouts: AtomicU64,
    takeovers: AtomicU64,
    post_flight_local_hits: AtomicU64,
    post_flight_retry_misses: AtomicU64,
    follower_wait_samples_ms: StdMutex<Vec<u64>>,
}

impl SingleflightMetrics {
    pub fn new() -> Self {
        Self {
            kinds: DashMap::new(),
        }
    }

    pub fn record_leader(&self, kind: &str) {
        self.kind(kind).leaders.fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_follower(&self, kind: &str) {
        self.kind(kind).followers.fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_follower_wait(&self, kind: &str, duration_ms: u64, completed: bool) {
        let metrics = self.kind(kind);
        if !completed {
            metrics.follower_timeouts.fetch_add(1, Ordering::AcqRel);
        }
        if let Ok(mut samples) = metrics.follower_wait_samples_ms.lock() {
            samples.push(duration_ms);
        }
    }

    pub fn record_takeover(&self, kind: &str) {
        self.kind(kind).takeovers.fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_post_flight_local_hit(&self, kind: &str) {
        self.kind(kind)
            .post_flight_local_hits
            .fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_post_flight_retry_miss(&self, kind: &str) {
        self.kind(kind)
            .post_flight_retry_misses
            .fetch_add(1, Ordering::AcqRel);
    }

    pub fn metadata_hints(&self) -> BTreeMap<String, String> {
        let mut hints = BTreeMap::new();
        for entry in &self.kinds {
            let kind = entry.key();
            let slug = metric_slug(kind);
            let metrics = entry.value();
            insert_counter(
                &mut hints,
                &format!("singleflight_{slug}_leaders"),
                &metrics.leaders,
            );
            insert_counter(
                &mut hints,
                &format!("singleflight_{slug}_followers"),
                &metrics.followers,
            );
            insert_counter(
                &mut hints,
                &format!("singleflight_{slug}_follower_timeouts"),
                &metrics.follower_timeouts,
            );
            insert_counter(
                &mut hints,
                &format!("singleflight_{slug}_takeovers"),
                &metrics.takeovers,
            );
            insert_counter(
                &mut hints,
                &format!("singleflight_{slug}_post_flight_local_hits"),
                &metrics.post_flight_local_hits,
            );
            insert_counter(
                &mut hints,
                &format!("singleflight_{slug}_post_flight_retry_misses"),
                &metrics.post_flight_retry_misses,
            );
            if let Ok(samples) = metrics.follower_wait_samples_ms.lock()
                && !samples.is_empty()
            {
                hints.insert(
                    format!("singleflight_{slug}_follower_wait_p50_ms"),
                    percentile(&samples, 50).to_string(),
                );
                hints.insert(
                    format!("singleflight_{slug}_follower_wait_p95_ms"),
                    percentile(&samples, 95).to_string(),
                );
            }
        }
        hints
    }

    fn kind(&self, kind: &str) -> Arc<SingleflightKindMetrics> {
        self.kinds
            .entry(kind.to_string())
            .or_insert_with(|| Arc::new(SingleflightKindMetrics::new()))
            .clone()
    }
}

impl Default for SingleflightMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl SingleflightKindMetrics {
    fn new() -> Self {
        Self {
            leaders: AtomicU64::new(0),
            followers: AtomicU64::new(0),
            follower_timeouts: AtomicU64::new(0),
            takeovers: AtomicU64::new(0),
            post_flight_local_hits: AtomicU64::new(0),
            post_flight_retry_misses: AtomicU64::new(0),
            follower_wait_samples_ms: StdMutex::new(Vec::new()),
        }
    }
}

fn insert_counter(hints: &mut BTreeMap<String, String>, name: &str, counter: &AtomicU64) {
    let value = counter.load(Ordering::Acquire);
    if value > 0 {
        hints.insert(name.to_string(), value.to_string());
    }
}

fn metric_slug(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .to_ascii_lowercase()
}

fn percentile(samples: &[u64], pct: u64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let index = (((pct as f64 / 100.0) * sorted.len() as f64).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[index]
}

pub struct OciEngineDiagnostics {
    proof_total: AtomicU64,
    proof_bytes: AtomicU64,
    proof_upload_session: AtomicU64,
    proof_mounted_session: AtomicU64,
    proof_manifest_reference_session: AtomicU64,
    proof_local_body_cache: AtomicU64,
    proof_remote_storage: AtomicU64,
    blob_local_reads: AtomicU64,
    blob_remote_reads: AtomicU64,
    blob_served_bytes: AtomicU64,
    blob_remote_fetched_bytes: AtomicU64,
    blob_read_throughs: AtomicU64,
    range_requests: AtomicU64,
    range_partial_responses: AtomicU64,
    range_invalid_responses: AtomicU64,
    graph_expansions: AtomicU64,
    graph_child_manifests: AtomicU64,
    graph_descriptors: AtomicU64,
    publish_total_count: AtomicU64,
    publish_total_duration_ms: AtomicU64,
    publish_save_count: AtomicU64,
    publish_save_duration_ms: AtomicU64,
    publish_blob_count: AtomicU64,
    publish_blob_duration_ms: AtomicU64,
    publish_pointer_count: AtomicU64,
    publish_pointer_duration_ms: AtomicU64,
    publish_confirm_count: AtomicU64,
    publish_confirm_duration_ms: AtomicU64,
    publish_alias_count: AtomicU64,
    publish_alias_duration_ms: AtomicU64,
    publish_referrers_count: AtomicU64,
    publish_referrers_duration_ms: AtomicU64,
    miss_blob_locator: AtomicU64,
    miss_remote_blob: AtomicU64,
    miss_manifest: AtomicU64,
    miss_download_url: AtomicU64,
    remote_blob_check_errors: AtomicU64,
    negative_cache_hit_manifest_ref: AtomicU64,
    negative_cache_hit_blob_locator: AtomicU64,
    negative_cache_hit_download_url: AtomicU64,
    negative_cache_hit_remote_blob: AtomicU64,
    negative_cache_insert_manifest_ref: AtomicU64,
    negative_cache_insert_blob_locator: AtomicU64,
    negative_cache_insert_download_url: AtomicU64,
    negative_cache_insert_remote_blob: AtomicU64,
    storage_get_count: AtomicU64,
    storage_get_ttfb_ms: AtomicU64,
    storage_get_body_duration_ms: AtomicU64,
    storage_get_bytes: AtomicU64,
    storage_get_retry_count: AtomicU64,
    storage_get_error_count: AtomicU64,
    storage_get_timeout_count: AtomicU64,
    storage_get_regions: StdMutex<BTreeMap<String, u64>>,
    storage_get_cache_statuses: StdMutex<BTreeMap<String, u64>>,
    storage_get_block_locations: StdMutex<BTreeMap<String, u64>>,
    local_spool_bytes: AtomicU64,
    local_spool_write_duration_ms: AtomicU64,
    digest_verify_duration_ms: AtomicU64,
    digest_verify_failures: AtomicU64,
    cache_promotion_count: AtomicU64,
    cache_promotion_duration_ms: AtomicU64,
    cache_promotion_failures: AtomicU64,
    upload_session_materialization_count: AtomicU64,
    upload_session_materialization_bytes: AtomicU64,
    upload_session_materialization_copy_duration_ms: AtomicU64,
    upload_session_materialization_sync_duration_ms: AtomicU64,
    borrowed_upload_session_count: AtomicU64,
    borrowed_upload_session_bytes: AtomicU64,
    stream_through_count: AtomicU64,
    stream_through_bytes: AtomicU64,
    stream_through_verify_duration_ms: AtomicU64,
    stream_through_verify_failures: AtomicU64,
    stream_through_cache_promotion_failures: AtomicU64,
    alias_promotion_promoted: AtomicU64,
    alias_promotion_unchanged: AtomicU64,
    alias_promotion_ignored_stale: AtomicU64,
    alias_promotion_failed: AtomicU64,
}

impl OciEngineDiagnostics {
    pub fn new() -> Self {
        Self {
            proof_total: AtomicU64::new(0),
            proof_bytes: AtomicU64::new(0),
            proof_upload_session: AtomicU64::new(0),
            proof_mounted_session: AtomicU64::new(0),
            proof_manifest_reference_session: AtomicU64::new(0),
            proof_local_body_cache: AtomicU64::new(0),
            proof_remote_storage: AtomicU64::new(0),
            blob_local_reads: AtomicU64::new(0),
            blob_remote_reads: AtomicU64::new(0),
            blob_served_bytes: AtomicU64::new(0),
            blob_remote_fetched_bytes: AtomicU64::new(0),
            blob_read_throughs: AtomicU64::new(0),
            range_requests: AtomicU64::new(0),
            range_partial_responses: AtomicU64::new(0),
            range_invalid_responses: AtomicU64::new(0),
            graph_expansions: AtomicU64::new(0),
            graph_child_manifests: AtomicU64::new(0),
            graph_descriptors: AtomicU64::new(0),
            publish_total_count: AtomicU64::new(0),
            publish_total_duration_ms: AtomicU64::new(0),
            publish_save_count: AtomicU64::new(0),
            publish_save_duration_ms: AtomicU64::new(0),
            publish_blob_count: AtomicU64::new(0),
            publish_blob_duration_ms: AtomicU64::new(0),
            publish_pointer_count: AtomicU64::new(0),
            publish_pointer_duration_ms: AtomicU64::new(0),
            publish_confirm_count: AtomicU64::new(0),
            publish_confirm_duration_ms: AtomicU64::new(0),
            publish_alias_count: AtomicU64::new(0),
            publish_alias_duration_ms: AtomicU64::new(0),
            publish_referrers_count: AtomicU64::new(0),
            publish_referrers_duration_ms: AtomicU64::new(0),
            miss_blob_locator: AtomicU64::new(0),
            miss_remote_blob: AtomicU64::new(0),
            miss_manifest: AtomicU64::new(0),
            miss_download_url: AtomicU64::new(0),
            remote_blob_check_errors: AtomicU64::new(0),
            negative_cache_hit_manifest_ref: AtomicU64::new(0),
            negative_cache_hit_blob_locator: AtomicU64::new(0),
            negative_cache_hit_download_url: AtomicU64::new(0),
            negative_cache_hit_remote_blob: AtomicU64::new(0),
            negative_cache_insert_manifest_ref: AtomicU64::new(0),
            negative_cache_insert_blob_locator: AtomicU64::new(0),
            negative_cache_insert_download_url: AtomicU64::new(0),
            negative_cache_insert_remote_blob: AtomicU64::new(0),
            storage_get_count: AtomicU64::new(0),
            storage_get_ttfb_ms: AtomicU64::new(0),
            storage_get_body_duration_ms: AtomicU64::new(0),
            storage_get_bytes: AtomicU64::new(0),
            storage_get_retry_count: AtomicU64::new(0),
            storage_get_error_count: AtomicU64::new(0),
            storage_get_timeout_count: AtomicU64::new(0),
            storage_get_regions: StdMutex::new(BTreeMap::new()),
            storage_get_cache_statuses: StdMutex::new(BTreeMap::new()),
            storage_get_block_locations: StdMutex::new(BTreeMap::new()),
            local_spool_bytes: AtomicU64::new(0),
            local_spool_write_duration_ms: AtomicU64::new(0),
            digest_verify_duration_ms: AtomicU64::new(0),
            digest_verify_failures: AtomicU64::new(0),
            cache_promotion_count: AtomicU64::new(0),
            cache_promotion_duration_ms: AtomicU64::new(0),
            cache_promotion_failures: AtomicU64::new(0),
            upload_session_materialization_count: AtomicU64::new(0),
            upload_session_materialization_bytes: AtomicU64::new(0),
            upload_session_materialization_copy_duration_ms: AtomicU64::new(0),
            upload_session_materialization_sync_duration_ms: AtomicU64::new(0),
            borrowed_upload_session_count: AtomicU64::new(0),
            borrowed_upload_session_bytes: AtomicU64::new(0),
            stream_through_count: AtomicU64::new(0),
            stream_through_bytes: AtomicU64::new(0),
            stream_through_verify_duration_ms: AtomicU64::new(0),
            stream_through_verify_failures: AtomicU64::new(0),
            stream_through_cache_promotion_failures: AtomicU64::new(0),
            alias_promotion_promoted: AtomicU64::new(0),
            alias_promotion_unchanged: AtomicU64::new(0),
            alias_promotion_ignored_stale: AtomicU64::new(0),
            alias_promotion_failed: AtomicU64::new(0),
        }
    }

    pub fn record_proof_source(&self, source: &str, bytes: u64) {
        self.proof_total.fetch_add(1, Ordering::AcqRel);
        self.proof_bytes.fetch_add(bytes, Ordering::AcqRel);
        match source {
            "upload-session" => &self.proof_upload_session,
            "mounted-session" => &self.proof_mounted_session,
            "manifest-reference-session" => &self.proof_manifest_reference_session,
            "local-body-cache" => &self.proof_local_body_cache,
            "remote-storage" => &self.proof_remote_storage,
            _ => return,
        }
        .fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_local_blob_read(&self, served_bytes: u64, ranged: bool) {
        self.blob_local_reads.fetch_add(1, Ordering::AcqRel);
        self.blob_served_bytes
            .fetch_add(served_bytes, Ordering::AcqRel);
        if ranged {
            self.range_partial_responses.fetch_add(1, Ordering::AcqRel);
        }
    }

    pub fn record_remote_blob_read(&self, served_bytes: u64, fetched_bytes: u64, ranged: bool) {
        self.blob_remote_reads.fetch_add(1, Ordering::AcqRel);
        self.blob_served_bytes
            .fetch_add(served_bytes, Ordering::AcqRel);
        self.blob_remote_fetched_bytes
            .fetch_add(fetched_bytes, Ordering::AcqRel);
        self.blob_read_throughs.fetch_add(1, Ordering::AcqRel);
        if ranged {
            self.range_partial_responses.fetch_add(1, Ordering::AcqRel);
        }
    }

    pub fn record_range_request(&self) {
        self.range_requests.fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_invalid_range(&self) {
        self.range_invalid_responses.fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_graph_expansion(&self, child_manifests: usize, descriptors: usize) {
        self.graph_expansions.fetch_add(1, Ordering::AcqRel);
        self.graph_child_manifests
            .fetch_add(child_manifests as u64, Ordering::AcqRel);
        self.graph_descriptors
            .fetch_add(descriptors as u64, Ordering::AcqRel);
    }

    pub fn record_publish_phase(&self, phase: &str, duration_ms: u64) {
        let (count, duration) = match phase {
            "total" => (&self.publish_total_count, &self.publish_total_duration_ms),
            "save" => (&self.publish_save_count, &self.publish_save_duration_ms),
            "blobs" => (&self.publish_blob_count, &self.publish_blob_duration_ms),
            "pointer" => (
                &self.publish_pointer_count,
                &self.publish_pointer_duration_ms,
            ),
            "confirm" => (
                &self.publish_confirm_count,
                &self.publish_confirm_duration_ms,
            ),
            "alias" => (&self.publish_alias_count, &self.publish_alias_duration_ms),
            "referrers" => (
                &self.publish_referrers_count,
                &self.publish_referrers_duration_ms,
            ),
            _ => return,
        };
        count.fetch_add(1, Ordering::AcqRel);
        duration.fetch_add(duration_ms, Ordering::AcqRel);
    }

    pub fn record_miss(&self, cause: &str) {
        match cause {
            "blob-locator" => &self.miss_blob_locator,
            "remote-blob" => &self.miss_remote_blob,
            "manifest" => &self.miss_manifest,
            "download-url" => &self.miss_download_url,
            _ => return,
        }
        .fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_negative_cache_hit(&self, reason: OciNegativeCacheReason) {
        match reason {
            OciNegativeCacheReason::ManifestRef => &self.negative_cache_hit_manifest_ref,
            OciNegativeCacheReason::BlobLocator => &self.negative_cache_hit_blob_locator,
            OciNegativeCacheReason::DownloadUrl => &self.negative_cache_hit_download_url,
            OciNegativeCacheReason::RemoteBlob => &self.negative_cache_hit_remote_blob,
        }
        .fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_negative_cache_insert(&self, reason: OciNegativeCacheReason) {
        match reason {
            OciNegativeCacheReason::ManifestRef => &self.negative_cache_insert_manifest_ref,
            OciNegativeCacheReason::BlobLocator => &self.negative_cache_insert_blob_locator,
            OciNegativeCacheReason::DownloadUrl => &self.negative_cache_insert_download_url,
            OciNegativeCacheReason::RemoteBlob => &self.negative_cache_insert_remote_blob,
        }
        .fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_remote_blob_check_error(&self) {
        self.remote_blob_check_errors.fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_storage_get(
        &self,
        bytes: u64,
        ttfb_ms: u64,
        body_duration_ms: u64,
        spool_write_duration_ms: u64,
        verify_duration_ms: u64,
        storage_metrics: Option<&crate::telemetry::StorageMetrics>,
    ) {
        self.storage_get_count.fetch_add(1, Ordering::AcqRel);
        self.storage_get_bytes.fetch_add(bytes, Ordering::AcqRel);
        self.storage_get_ttfb_ms
            .fetch_add(ttfb_ms, Ordering::AcqRel);
        self.storage_get_body_duration_ms
            .fetch_add(body_duration_ms, Ordering::AcqRel);
        self.local_spool_bytes.fetch_add(bytes, Ordering::AcqRel);
        self.local_spool_write_duration_ms
            .fetch_add(spool_write_duration_ms, Ordering::AcqRel);
        self.digest_verify_duration_ms
            .fetch_add(verify_duration_ms, Ordering::AcqRel);
        if let Some(metrics) = storage_metrics {
            self.record_storage_label(&self.storage_get_regions, metrics.region.as_deref());
            self.record_storage_label(
                &self.storage_get_cache_statuses,
                metrics.cache_status.as_deref(),
            );
            self.record_storage_label(
                &self.storage_get_block_locations,
                metrics.block_location.as_deref(),
            );
        }
    }

    pub fn record_storage_get_retry(&self) {
        self.storage_get_retry_count.fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_storage_get_error(&self) {
        self.storage_get_error_count.fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_storage_get_timeout(&self) {
        self.storage_get_timeout_count
            .fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_digest_verify_failure(&self) {
        self.digest_verify_failures.fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_cache_promotion(&self, duration_ms: u64, ok: bool) {
        self.cache_promotion_count.fetch_add(1, Ordering::AcqRel);
        self.cache_promotion_duration_ms
            .fetch_add(duration_ms, Ordering::AcqRel);
        if !ok {
            self.cache_promotion_failures.fetch_add(1, Ordering::AcqRel);
        }
    }

    pub fn record_upload_session_materialization(
        &self,
        bytes: u64,
        copy_duration_ms: u64,
        sync_duration_ms: u64,
    ) {
        self.upload_session_materialization_count
            .fetch_add(1, Ordering::AcqRel);
        self.upload_session_materialization_bytes
            .fetch_add(bytes, Ordering::AcqRel);
        self.upload_session_materialization_copy_duration_ms
            .fetch_add(copy_duration_ms, Ordering::AcqRel);
        self.upload_session_materialization_sync_duration_ms
            .fetch_add(sync_duration_ms, Ordering::AcqRel);
    }

    pub fn record_borrowed_upload_session(&self, bytes: u64) {
        self.borrowed_upload_session_count
            .fetch_add(1, Ordering::AcqRel);
        self.borrowed_upload_session_bytes
            .fetch_add(bytes, Ordering::AcqRel);
    }

    pub fn record_stream_through(
        &self,
        bytes: u64,
        verify_duration_ms: u64,
        cache_promotion_ok: bool,
    ) {
        self.stream_through_count.fetch_add(1, Ordering::AcqRel);
        self.stream_through_bytes.fetch_add(bytes, Ordering::AcqRel);
        self.stream_through_verify_duration_ms
            .fetch_add(verify_duration_ms, Ordering::AcqRel);
        if !cache_promotion_ok {
            self.stream_through_cache_promotion_failures
                .fetch_add(1, Ordering::AcqRel);
        }
    }

    pub fn record_stream_through_verify_failure(&self) {
        self.stream_through_verify_failures
            .fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_alias_promotion(&self, status: Option<&str>) {
        match status.unwrap_or("unknown") {
            "promoted" => &self.alias_promotion_promoted,
            "unchanged" => &self.alias_promotion_unchanged,
            "ignored_stale" => &self.alias_promotion_ignored_stale,
            _ => &self.alias_promotion_failed,
        }
        .fetch_add(1, Ordering::AcqRel);
    }

    pub fn metadata_hints(&self, hydration_policy: &str) -> BTreeMap<String, String> {
        let mut hints = BTreeMap::from([(
            "oci_engine_hydration_policy".to_string(),
            hydration_policy.to_string(),
        )]);

        self.insert_counter(&mut hints, "oci_engine_proof_total", &self.proof_total);
        self.insert_counter(&mut hints, "oci_engine_proof_bytes", &self.proof_bytes);
        self.insert_counter(
            &mut hints,
            "oci_engine_proof_upload_session",
            &self.proof_upload_session,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_proof_mounted_session",
            &self.proof_mounted_session,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_proof_manifest_reference_session",
            &self.proof_manifest_reference_session,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_proof_local_body_cache",
            &self.proof_local_body_cache,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_proof_remote_storage",
            &self.proof_remote_storage,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_blob_local_reads",
            &self.blob_local_reads,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_blob_remote_reads",
            &self.blob_remote_reads,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_blob_served_bytes",
            &self.blob_served_bytes,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_blob_remote_fetched_bytes",
            &self.blob_remote_fetched_bytes,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_blob_read_throughs",
            &self.blob_read_throughs,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_range_requests",
            &self.range_requests,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_range_partial_responses",
            &self.range_partial_responses,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_range_invalid_responses",
            &self.range_invalid_responses,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_graph_expansions",
            &self.graph_expansions,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_graph_child_manifests",
            &self.graph_child_manifests,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_graph_descriptors",
            &self.graph_descriptors,
        );
        self.insert_publish_phase(
            &mut hints,
            "total",
            &self.publish_total_count,
            &self.publish_total_duration_ms,
        );
        self.insert_publish_phase(
            &mut hints,
            "save",
            &self.publish_save_count,
            &self.publish_save_duration_ms,
        );
        self.insert_publish_phase(
            &mut hints,
            "blobs",
            &self.publish_blob_count,
            &self.publish_blob_duration_ms,
        );
        self.insert_publish_phase(
            &mut hints,
            "pointer",
            &self.publish_pointer_count,
            &self.publish_pointer_duration_ms,
        );
        self.insert_publish_phase(
            &mut hints,
            "confirm",
            &self.publish_confirm_count,
            &self.publish_confirm_duration_ms,
        );
        self.insert_publish_phase(
            &mut hints,
            "alias",
            &self.publish_alias_count,
            &self.publish_alias_duration_ms,
        );
        self.insert_publish_phase(
            &mut hints,
            "referrers",
            &self.publish_referrers_count,
            &self.publish_referrers_duration_ms,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_miss_blob_locator",
            &self.miss_blob_locator,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_miss_remote_blob",
            &self.miss_remote_blob,
        );
        self.insert_counter(&mut hints, "oci_engine_miss_manifest", &self.miss_manifest);
        self.insert_counter(
            &mut hints,
            "oci_engine_miss_download_url",
            &self.miss_download_url,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_remote_blob_check_errors",
            &self.remote_blob_check_errors,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_negative_cache_hit_manifest_ref",
            &self.negative_cache_hit_manifest_ref,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_negative_cache_hit_blob_locator",
            &self.negative_cache_hit_blob_locator,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_negative_cache_hit_download_url",
            &self.negative_cache_hit_download_url,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_negative_cache_hit_remote_blob",
            &self.negative_cache_hit_remote_blob,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_negative_cache_insert_manifest_ref",
            &self.negative_cache_insert_manifest_ref,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_negative_cache_insert_blob_locator",
            &self.negative_cache_insert_blob_locator,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_negative_cache_insert_download_url",
            &self.negative_cache_insert_download_url,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_negative_cache_insert_remote_blob",
            &self.negative_cache_insert_remote_blob,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_storage_get_count",
            &self.storage_get_count,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_storage_get_bytes",
            &self.storage_get_bytes,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_storage_get_ttfb_ms",
            &self.storage_get_ttfb_ms,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_storage_get_body_duration_ms",
            &self.storage_get_body_duration_ms,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_storage_get_retry_count",
            &self.storage_get_retry_count,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_storage_get_error_count",
            &self.storage_get_error_count,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_storage_get_timeout_count",
            &self.storage_get_timeout_count,
        );
        self.insert_top_label(
            &mut hints,
            "oci_engine_storage_region",
            &self.storage_get_regions,
        );
        self.insert_top_label(
            &mut hints,
            "oci_engine_storage_cache_status",
            &self.storage_get_cache_statuses,
        );
        self.insert_top_label(
            &mut hints,
            "oci_engine_storage_block_location",
            &self.storage_get_block_locations,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_local_spool_bytes",
            &self.local_spool_bytes,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_local_spool_write_duration_ms",
            &self.local_spool_write_duration_ms,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_digest_verify_duration_ms",
            &self.digest_verify_duration_ms,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_digest_verify_failures",
            &self.digest_verify_failures,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_cache_promotion_count",
            &self.cache_promotion_count,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_cache_promotion_duration_ms",
            &self.cache_promotion_duration_ms,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_cache_promotion_failures",
            &self.cache_promotion_failures,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_upload_session_materialization_count",
            &self.upload_session_materialization_count,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_upload_session_materialization_bytes",
            &self.upload_session_materialization_bytes,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_upload_session_materialization_copy_duration_ms",
            &self.upload_session_materialization_copy_duration_ms,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_upload_session_materialization_sync_duration_ms",
            &self.upload_session_materialization_sync_duration_ms,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_borrowed_upload_session_count",
            &self.borrowed_upload_session_count,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_borrowed_upload_session_bytes",
            &self.borrowed_upload_session_bytes,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_stream_through_count",
            &self.stream_through_count,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_stream_through_bytes",
            &self.stream_through_bytes,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_stream_through_verify_duration_ms",
            &self.stream_through_verify_duration_ms,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_stream_through_verify_failures",
            &self.stream_through_verify_failures,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_stream_through_cache_promotion_failures",
            &self.stream_through_cache_promotion_failures,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_alias_promotion_promoted",
            &self.alias_promotion_promoted,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_alias_promotion_unchanged",
            &self.alias_promotion_unchanged,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_alias_promotion_ignored_stale",
            &self.alias_promotion_ignored_stale,
        );
        self.insert_counter(
            &mut hints,
            "oci_engine_alias_promotion_failed",
            &self.alias_promotion_failed,
        );

        hints
    }

    fn insert_counter(
        &self,
        hints: &mut BTreeMap<String, String>,
        name: &str,
        counter: &AtomicU64,
    ) {
        let value = counter.load(Ordering::Acquire);
        if value > 0 {
            hints.insert(name.to_string(), value.to_string());
        }
    }

    fn record_storage_label(&self, counts: &StdMutex<BTreeMap<String, u64>>, label: Option<&str>) {
        let Some(label) = normalize_storage_label(label) else {
            return;
        };
        if let Ok(mut locked) = counts.try_lock() {
            let value = locked.entry(label).or_insert(0);
            *value = value.saturating_add(1);
        }
    }

    fn insert_top_label(
        &self,
        hints: &mut BTreeMap<String, String>,
        name: &str,
        counts: &StdMutex<BTreeMap<String, u64>>,
    ) {
        let Ok(locked) = counts.try_lock() else {
            return;
        };
        let Some((label, count)) = locked
            .iter()
            .max_by(|left, right| left.1.cmp(right.1).then_with(|| right.0.cmp(left.0)))
        else {
            return;
        };
        hints.insert(name.to_string(), label.clone());
        hints.insert(format!("{name}_count"), count.to_string());
    }

    fn insert_publish_phase(
        &self,
        hints: &mut BTreeMap<String, String>,
        phase: &str,
        count: &AtomicU64,
        duration: &AtomicU64,
    ) {
        let count_value = count.load(Ordering::Acquire);
        if count_value == 0 {
            return;
        }
        let duration_value = duration.load(Ordering::Acquire);
        hints.insert(
            format!("oci_engine_publish_{phase}_count"),
            count_value.to_string(),
        );
        hints.insert(
            format!("oci_engine_publish_{phase}_duration_ms"),
            duration_value.to_string(),
        );
    }
}

fn normalize_storage_label(label: Option<&str>) -> Option<String> {
    let label = label?.trim().trim_matches('"');
    if label.is_empty() {
        return None;
    }
    Some(label.chars().take(64).collect())
}

impl Default for OciEngineDiagnostics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
struct StartupPrefetchSnapshot {
    mode: Option<String>,
    total_unique_blobs: u64,
    target_blobs: u64,
    target_bytes: u64,
    average_blob_bytes: u64,
    max_concurrency: u64,
    concurrency: u64,
    initial_concurrency: u64,
    final_concurrency: u64,
    max_observed_concurrency: u64,
    concurrency_adjustment_count: u64,
    concurrency_adjustments: Vec<String>,
    concurrency_source: Option<String>,
    concurrency_reason: Option<String>,
    url_resolved: u64,
    url_missing: u64,
    already_local: u64,
    inserted: u64,
    failures: u64,
    cold_blobs: u64,
    duration_ms: u64,
    timed_out: bool,
    oci_hydration_policy: Option<String>,
    oci_refs: u64,
    oci_total_unique_blobs: u64,
    oci_inserted: u64,
    oci_failures: u64,
    oci_cold_blobs: u64,
    oci_duration_ms: u64,
    oci_body_inserted: u64,
    oci_body_failures: u64,
    oci_body_cold_blobs: u64,
    oci_body_duration_ms: u64,
}

pub struct StartupOciExecution<'a> {
    pub hydration_policy: &'a str,
    pub refs: usize,
    pub total_unique_blobs: usize,
    pub inserted: usize,
    pub failures: usize,
    pub cold_blobs: usize,
    pub duration_ms: u64,
}

pub struct StartupPrefetchPlan<'a> {
    pub mode: &'a str,
    pub total_unique_blobs: usize,
    pub target_blobs: usize,
    pub target_bytes: u64,
    pub max_concurrency: usize,
    pub effective_concurrency: usize,
    pub initial_concurrency: usize,
    pub concurrency_source: &'a str,
    pub concurrency_reason: &'a str,
}

pub struct PrefetchMetrics {
    startup: StdMutex<StartupPrefetchSnapshot>,
}

impl PrefetchMetrics {
    pub fn new() -> Self {
        Self {
            startup: StdMutex::new(StartupPrefetchSnapshot::default()),
        }
    }

    pub fn reset_startup(&self) {
        if let Ok(mut snapshot) = self.startup.lock() {
            *snapshot = StartupPrefetchSnapshot::default();
        }
    }

    pub fn record_startup_plan(&self, plan: StartupPrefetchPlan<'_>) {
        if let Ok(mut snapshot) = self.startup.lock() {
            snapshot.mode = Some(plan.mode.to_string());
            snapshot.total_unique_blobs = plan.total_unique_blobs as u64;
            snapshot.target_blobs = plan.target_blobs as u64;
            snapshot.target_bytes = plan.target_bytes;
            snapshot.average_blob_bytes = if plan.target_blobs > 0 {
                plan.target_bytes / plan.target_blobs as u64
            } else {
                0
            };
            snapshot.max_concurrency = plan.max_concurrency as u64;
            snapshot.concurrency = plan.effective_concurrency as u64;
            snapshot.initial_concurrency = plan.initial_concurrency as u64;
            snapshot.final_concurrency = plan.initial_concurrency as u64;
            snapshot.max_observed_concurrency = plan.initial_concurrency as u64;
            snapshot.concurrency_source = Some(plan.concurrency_source.to_string());
            snapshot.concurrency_reason = Some(plan.concurrency_reason.to_string());
        }
    }

    pub fn record_startup_concurrency_adjustment(
        &self,
        adjustment: &str,
        previous: usize,
        next: usize,
    ) {
        if let Ok(mut snapshot) = self.startup.lock() {
            snapshot.concurrency_adjustment_count =
                snapshot.concurrency_adjustment_count.saturating_add(1);
            if snapshot.concurrency_adjustments.len() < 32 {
                snapshot
                    .concurrency_adjustments
                    .push(format!("{adjustment}:{previous}->{next}"));
            }
        }
    }

    pub fn record_startup_concurrency_observed(
        &self,
        final_concurrency: usize,
        max_observed_concurrency: usize,
    ) {
        if let Ok(mut snapshot) = self.startup.lock() {
            snapshot.final_concurrency = final_concurrency as u64;
            snapshot.max_observed_concurrency = max_observed_concurrency as u64;
        }
    }

    pub fn record_startup_url_coverage(&self, resolved: usize, missing: usize) {
        if let Ok(mut snapshot) = self.startup.lock() {
            snapshot.url_resolved = resolved as u64;
            snapshot.url_missing = missing as u64;
        }
    }

    pub fn record_startup_execution(
        &self,
        already_local: usize,
        inserted: usize,
        failures: usize,
        duration_ms: u64,
    ) {
        if let Ok(mut snapshot) = self.startup.lock() {
            snapshot.already_local = already_local as u64;
            snapshot.inserted = inserted as u64;
            snapshot.failures = failures as u64;
            snapshot.duration_ms = duration_ms;
        }
    }

    pub fn record_startup_cold_blobs(&self, cold_blobs: usize) {
        if let Ok(mut snapshot) = self.startup.lock() {
            snapshot.cold_blobs = cold_blobs as u64;
        }
    }

    pub fn record_startup_timeout(&self) {
        if let Ok(mut snapshot) = self.startup.lock() {
            snapshot.timed_out = true;
        }
    }

    pub fn record_startup_oci_execution(&self, execution: StartupOciExecution<'_>) {
        if let Ok(mut snapshot) = self.startup.lock() {
            snapshot.oci_hydration_policy = Some(execution.hydration_policy.to_string());
            snapshot.oci_refs = snapshot.oci_refs.saturating_add(execution.refs as u64);
            snapshot.oci_total_unique_blobs = snapshot
                .oci_total_unique_blobs
                .saturating_add(execution.total_unique_blobs as u64);
            snapshot.oci_inserted = snapshot
                .oci_inserted
                .saturating_add(execution.inserted as u64);
            snapshot.oci_failures = snapshot
                .oci_failures
                .saturating_add(execution.failures as u64);
            snapshot.oci_cold_blobs = snapshot
                .oci_cold_blobs
                .saturating_add(execution.cold_blobs as u64);
            snapshot.oci_duration_ms = snapshot
                .oci_duration_ms
                .saturating_add(execution.duration_ms);
        }
    }

    pub fn record_startup_oci_body_snapshot(
        &self,
        inserted: usize,
        failures: usize,
        cold_blobs: usize,
        duration_ms: u64,
    ) {
        if let Ok(mut snapshot) = self.startup.lock() {
            snapshot.oci_body_inserted = inserted as u64;
            snapshot.oci_body_failures = failures as u64;
            snapshot.oci_body_cold_blobs = cold_blobs as u64;
            snapshot.oci_body_duration_ms = duration_ms;
        }
    }

    pub fn metadata_hints(&self) -> BTreeMap<String, String> {
        let Ok(snapshot) = self.startup.lock() else {
            return BTreeMap::new();
        };
        if snapshot.target_blobs == 0
            && snapshot.total_unique_blobs == 0
            && snapshot.oci_refs == 0
            && !snapshot.timed_out
        {
            return BTreeMap::new();
        }

        let mut hints = BTreeMap::new();
        if let Some(mode) = &snapshot.mode {
            hints.insert("startup_prefetch_mode".to_string(), mode.clone());
        }
        hints.insert(
            "startup_prefetch_total_unique_blobs".to_string(),
            snapshot.total_unique_blobs.to_string(),
        );
        hints.insert(
            "startup_prefetch_target_blobs".to_string(),
            snapshot.target_blobs.to_string(),
        );
        hints.insert(
            "startup_prefetch_target_bytes".to_string(),
            snapshot.target_bytes.to_string(),
        );
        hints.insert(
            "startup_prefetch_average_blob_bytes".to_string(),
            snapshot.average_blob_bytes.to_string(),
        );
        hints.insert(
            "startup_prefetch_max_concurrency".to_string(),
            snapshot.max_concurrency.to_string(),
        );
        hints.insert(
            "startup_prefetch_concurrency".to_string(),
            snapshot.concurrency.to_string(),
        );
        hints.insert(
            "startup_prefetch_initial_concurrency".to_string(),
            snapshot.initial_concurrency.to_string(),
        );
        hints.insert(
            "startup_prefetch_final_concurrency".to_string(),
            snapshot.final_concurrency.to_string(),
        );
        hints.insert(
            "startup_prefetch_max_observed_concurrency".to_string(),
            snapshot.max_observed_concurrency.to_string(),
        );
        hints.insert(
            "startup_prefetch_concurrency_adjustment_count".to_string(),
            snapshot.concurrency_adjustment_count.to_string(),
        );
        if !snapshot.concurrency_adjustments.is_empty() {
            hints.insert(
                "startup_prefetch_concurrency_adjustments".to_string(),
                snapshot.concurrency_adjustments.join(","),
            );
        }
        if let Some(source) = &snapshot.concurrency_source {
            hints.insert(
                "startup_prefetch_concurrency_source".to_string(),
                source.clone(),
            );
        }
        if let Some(reason) = &snapshot.concurrency_reason {
            hints.insert(
                "startup_prefetch_concurrency_reason".to_string(),
                reason.clone(),
            );
        }
        hints.insert(
            "startup_prefetch_url_resolved".to_string(),
            snapshot.url_resolved.to_string(),
        );
        hints.insert(
            "startup_prefetch_url_missing".to_string(),
            snapshot.url_missing.to_string(),
        );
        hints.insert(
            "startup_prefetch_already_local".to_string(),
            snapshot.already_local.to_string(),
        );
        hints.insert(
            "startup_prefetch_inserted".to_string(),
            snapshot.inserted.to_string(),
        );
        hints.insert(
            "startup_prefetch_failures".to_string(),
            snapshot.failures.to_string(),
        );
        hints.insert(
            "startup_prefetch_cold_blobs".to_string(),
            snapshot.cold_blobs.to_string(),
        );
        hints.insert(
            "startup_prefetch_duration_ms".to_string(),
            snapshot.duration_ms.to_string(),
        );
        if snapshot.duration_ms > 0 {
            hints.insert(
                "startup_prefetch_blobs_per_sec".to_string(),
                ((snapshot.inserted.saturating_mul(1000)) / snapshot.duration_ms).to_string(),
            );
            hints.insert(
                "startup_prefetch_bytes_per_sec".to_string(),
                ((snapshot.target_bytes.saturating_mul(1000)) / snapshot.duration_ms).to_string(),
            );
        }
        if snapshot.timed_out {
            hints.insert("startup_prefetch_timed_out".to_string(), "true".to_string());
        }
        if snapshot.oci_refs > 0 {
            if let Some(policy) = &snapshot.oci_hydration_policy {
                hints.insert("startup_prefetch_oci_hydration".to_string(), policy.clone());
            }
            hints.insert(
                "startup_prefetch_oci_refs".to_string(),
                snapshot.oci_refs.to_string(),
            );
            hints.insert(
                "startup_prefetch_oci_total_unique_blobs".to_string(),
                snapshot.oci_total_unique_blobs.to_string(),
            );
            hints.insert(
                "startup_prefetch_oci_inserted".to_string(),
                snapshot.oci_inserted.to_string(),
            );
            hints.insert(
                "startup_prefetch_oci_failures".to_string(),
                snapshot.oci_failures.to_string(),
            );
            hints.insert(
                "startup_prefetch_oci_cold_blobs".to_string(),
                snapshot.oci_cold_blobs.to_string(),
            );
            hints.insert(
                "startup_prefetch_oci_duration_ms".to_string(),
                snapshot.oci_duration_ms.to_string(),
            );
            hints.insert(
                "startup_prefetch_oci_body_inserted".to_string(),
                snapshot.oci_body_inserted.to_string(),
            );
            hints.insert(
                "startup_prefetch_oci_body_failures".to_string(),
                snapshot.oci_body_failures.to_string(),
            );
            hints.insert(
                "startup_prefetch_oci_body_cold_blobs".to_string(),
                snapshot.oci_body_cold_blobs.to_string(),
            );
            hints.insert(
                "startup_prefetch_oci_body_duration_ms".to_string(),
                snapshot.oci_body_duration_ms.to_string(),
            );
        }
        hints
    }
}

impl Default for PrefetchMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
struct KvBlobUploadSnapshot {
    batches: u64,
    requested_blobs: u64,
    uploaded_blobs: u64,
    already_present_blobs: u64,
    missing_local_blobs: u64,
    failed_blobs: u64,
    duration_ms: u64,
    max_initial_concurrency: u64,
    max_allowed_concurrency: u64,
    max_final_concurrency: u64,
    last_concurrency_source: Option<String>,
    last_concurrency_reason: Option<String>,
}

pub struct KvBlobUploadBatch<'a> {
    pub requested_blobs: u64,
    pub uploaded_blobs: u64,
    pub already_present_blobs: u64,
    pub missing_local_blobs: u64,
    pub failed_blobs: u64,
    pub duration_ms: u64,
    pub initial_concurrency: usize,
    pub max_concurrency: usize,
    pub final_concurrency: usize,
    pub concurrency_source: &'a str,
    pub concurrency_reason: &'a str,
}

pub struct KvBlobUploadMetrics {
    snapshot: StdMutex<KvBlobUploadSnapshot>,
}

impl KvBlobUploadMetrics {
    pub fn new() -> Self {
        Self {
            snapshot: StdMutex::new(KvBlobUploadSnapshot::default()),
        }
    }

    pub fn record_batch(&self, batch: KvBlobUploadBatch<'_>) {
        if let Ok(mut snapshot) = self.snapshot.lock() {
            snapshot.batches = snapshot.batches.saturating_add(1);
            snapshot.requested_blobs = snapshot
                .requested_blobs
                .saturating_add(batch.requested_blobs);
            snapshot.uploaded_blobs = snapshot.uploaded_blobs.saturating_add(batch.uploaded_blobs);
            snapshot.already_present_blobs = snapshot
                .already_present_blobs
                .saturating_add(batch.already_present_blobs);
            snapshot.missing_local_blobs = snapshot
                .missing_local_blobs
                .saturating_add(batch.missing_local_blobs);
            snapshot.failed_blobs = snapshot.failed_blobs.saturating_add(batch.failed_blobs);
            snapshot.duration_ms = snapshot.duration_ms.saturating_add(batch.duration_ms);
            snapshot.max_initial_concurrency = snapshot
                .max_initial_concurrency
                .max(batch.initial_concurrency as u64);
            snapshot.max_allowed_concurrency = snapshot
                .max_allowed_concurrency
                .max(batch.max_concurrency as u64);
            snapshot.max_final_concurrency = snapshot
                .max_final_concurrency
                .max(batch.final_concurrency as u64);
            snapshot.last_concurrency_source = Some(batch.concurrency_source.to_string());
            snapshot.last_concurrency_reason = Some(batch.concurrency_reason.to_string());
        }
    }

    pub fn metadata_hints(&self) -> BTreeMap<String, String> {
        let Ok(snapshot) = self.snapshot.lock() else {
            return BTreeMap::new();
        };
        if snapshot.batches == 0 {
            return BTreeMap::new();
        }

        let mut hints = BTreeMap::new();
        hints.insert(
            "kv_upload_batches".to_string(),
            snapshot.batches.to_string(),
        );
        hints.insert(
            "kv_upload_requested_blobs".to_string(),
            snapshot.requested_blobs.to_string(),
        );
        hints.insert(
            "kv_upload_uploaded_blobs".to_string(),
            snapshot.uploaded_blobs.to_string(),
        );
        hints.insert(
            "kv_upload_already_present_blobs".to_string(),
            snapshot.already_present_blobs.to_string(),
        );
        hints.insert(
            "kv_upload_missing_local_blobs".to_string(),
            snapshot.missing_local_blobs.to_string(),
        );
        hints.insert(
            "kv_upload_failed_blobs".to_string(),
            snapshot.failed_blobs.to_string(),
        );
        hints.insert(
            "kv_upload_duration_ms".to_string(),
            snapshot.duration_ms.to_string(),
        );
        hints.insert(
            "kv_upload_initial_concurrency_max".to_string(),
            snapshot.max_initial_concurrency.to_string(),
        );
        hints.insert(
            "kv_upload_allowed_concurrency_max".to_string(),
            snapshot.max_allowed_concurrency.to_string(),
        );
        hints.insert(
            "kv_upload_final_concurrency_max".to_string(),
            snapshot.max_final_concurrency.to_string(),
        );
        if snapshot.duration_ms > 0 {
            hints.insert(
                "kv_upload_blobs_per_sec".to_string(),
                ((snapshot.uploaded_blobs.saturating_mul(1000)) / snapshot.duration_ms).to_string(),
            );
        }
        if let Some(source) = &snapshot.last_concurrency_source {
            hints.insert("kv_upload_concurrency_source".to_string(), source.clone());
        }
        if let Some(reason) = &snapshot.last_concurrency_reason {
            hints.insert("kv_upload_concurrency_reason".to_string(), reason.clone());
        }
        hints
    }
}

impl Default for KvBlobUploadMetrics {
    fn default() -> Self {
        Self::new()
    }
}

const BACKEND_BREAKER_OPEN_DURATION_MS: u64 = 8_000;
const BACKEND_BREAKER_FAILURE_THRESHOLD: u32 = 3;

pub struct BackendCircuitBreaker {
    open_until: AtomicU64,
    consecutive_failures: std::sync::atomic::AtomicU32,
}

impl BackendCircuitBreaker {
    pub fn new() -> Self {
        Self {
            open_until: AtomicU64::new(0),
            consecutive_failures: std::sync::atomic::AtomicU32::new(0),
        }
    }

    pub fn is_open(&self) -> bool {
        let until = self.open_until.load(Ordering::Acquire);
        until > 0 && unix_time_ms_now() < until
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Release);
        self.open_until.store(0, Ordering::Release);
    }

    pub fn record_failure(&self) {
        let prev = self.consecutive_failures.fetch_add(1, Ordering::AcqRel);
        if prev + 1 >= BACKEND_BREAKER_FAILURE_THRESHOLD {
            let until = unix_time_ms_now() + BACKEND_BREAKER_OPEN_DURATION_MS;
            self.open_until.store(until, Ordering::Release);
        }
    }
}

impl Default for BackendCircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}
