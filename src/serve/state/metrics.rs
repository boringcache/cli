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

    pub fn record_startup_plan(
        &self,
        mode: &str,
        total_unique_blobs: usize,
        target_blobs: usize,
        target_bytes: u64,
    ) {
        if let Ok(mut snapshot) = self.startup.lock() {
            snapshot.mode = Some(mode.to_string());
            snapshot.total_unique_blobs = total_unique_blobs as u64;
            snapshot.target_blobs = target_blobs as u64;
            snapshot.target_bytes = target_bytes;
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
