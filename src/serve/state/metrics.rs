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
    duration_ms: u64,
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

    pub fn metadata_hints(&self) -> BTreeMap<String, String> {
        let Ok(snapshot) = self.startup.lock() else {
            return BTreeMap::new();
        };
        if snapshot.target_blobs == 0 && snapshot.total_unique_blobs == 0 {
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
            "startup_prefetch_duration_ms".to_string(),
            snapshot.duration_ms.to_string(),
        );
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
