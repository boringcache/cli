use crate::api::ApiClient;

use super::StorageMetrics;

pub struct SaveMetrics {
    pub tag: String,
    pub manifest_root_digest: String,
    pub total_duration_ms: u64,
    pub archive_duration_ms: u64,
    pub upload_duration_ms: u64,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
    pub file_count: u32,
    pub part_count: Option<u32>,
    pub storage_metrics: StorageMetrics,
}

pub struct RestoreMetrics {
    pub tag: String,
    pub manifest_root_digest: Option<String>,
    pub total_duration_ms: u64,
    pub download_duration_ms: u64,
    pub extract_duration_ms: u64,
    pub compressed_size: u64,
    pub storage_metrics: StorageMetrics,
}

struct OperationMetrics {
    operation_type: String,
    tag: String,
    manifest_root_digest: Option<String>,
    total_duration_ms: u64,
    archive_duration_ms: Option<u64>,
    upload_duration_ms: Option<u64>,
    download_duration_ms: Option<u64>,
    extract_duration_ms: Option<u64>,
    uncompressed_size: Option<u64>,
    compressed_size: Option<u64>,
    file_count: Option<u32>,
    part_count: Option<u32>,
    storage_metrics: StorageMetrics,
}

impl From<SaveMetrics> for OperationMetrics {
    fn from(m: SaveMetrics) -> Self {
        Self {
            operation_type: "save".to_string(),
            tag: m.tag,
            manifest_root_digest: Some(m.manifest_root_digest),
            total_duration_ms: m.total_duration_ms,
            archive_duration_ms: Some(m.archive_duration_ms),
            upload_duration_ms: Some(m.upload_duration_ms),
            download_duration_ms: None,
            extract_duration_ms: None,
            uncompressed_size: Some(m.uncompressed_size),
            compressed_size: Some(m.compressed_size),
            file_count: Some(m.file_count),
            part_count: m.part_count,
            storage_metrics: m.storage_metrics,
        }
    }
}

impl From<RestoreMetrics> for OperationMetrics {
    fn from(m: RestoreMetrics) -> Self {
        Self {
            operation_type: "restore".to_string(),
            tag: m.tag,
            manifest_root_digest: m.manifest_root_digest,
            total_duration_ms: m.total_duration_ms,
            archive_duration_ms: None,
            upload_duration_ms: None,
            download_duration_ms: Some(m.download_duration_ms),
            extract_duration_ms: Some(m.extract_duration_ms),
            uncompressed_size: None,
            compressed_size: Some(m.compressed_size),
            file_count: None,
            part_count: None,
            storage_metrics: m.storage_metrics,
        }
    }
}

impl OperationMetrics {
    async fn send(self, api_client: &ApiClient, workspace: &str) {
        if std::env::var("BORINGCACHE_TELEMETRY_DISABLED").is_ok() {
            return;
        }

        let upload_speed_mbps = match (self.upload_duration_ms, self.compressed_size) {
            (Some(duration_ms), Some(size)) if duration_ms > 0 => {
                Some((size as f64 / 1_000_000.0) / (duration_ms as f64 / 1000.0) * 8.0)
            }
            _ => None,
        };

        let download_speed_mbps = match (self.download_duration_ms, self.compressed_size) {
            (Some(duration_ms), Some(size)) if duration_ms > 0 => {
                Some((size as f64 / 1_000_000.0) / (duration_ms as f64 / 1000.0) * 8.0)
            }
            _ => None,
        };

        let metrics = crate::api::MetricsParams {
            operation_type: self.operation_type,
            cache_path: None,
            manifest_root_digest: self.manifest_root_digest,
            total_duration: self.total_duration_ms,
            archive_duration: self.archive_duration_ms,
            upload_duration: self.upload_duration_ms,
            download_duration: self.download_duration_ms,
            extract_duration: self.extract_duration_ms,
            confirm_duration: None,
            uncompressed_size: self.uncompressed_size,
            compressed_size: self.compressed_size,
            compression_ratio: None,
            file_count: self.file_count,
            upload_speed_mbps,
            download_speed_mbps,
            cache_age_hours: None,
            error_message: None,
            benchmark_compression_ratio: None,
            compression_duration: None,
            predicted_time_ms: None,
            prediction_accuracy: None,
            tags: Some(vec![self.tag]),
            compression_algorithm: Some("zstd".to_string()),
            cpu_cores: None,
            cpu_load_percent: None,
            total_memory_gb: None,
            available_memory_gb: None,
            memory_strategy: None,
            disk_type: None,
            disk_speed_estimate_mb_s: None,
            concurrent_operations: None,
            buffer_size_mb: None,
            part_size_mb: None,
            concurrency_level: None,
            streaming_enabled: None,
            compression_level: None,
            compression_threads: None,
            benchmark_throughput_mb_s: None,
            bandwidth_probe_mb_s: None,
            multipart_threshold_mb: None,
            part_count: self.part_count,
            retry_count: None,
            transfer_size: self.compressed_size,
            cache_efficiency: None,
            storage_region: self.storage_metrics.region,
            storage_cache_status: self.storage_metrics.cache_status,
            storage_block_location: self.storage_metrics.block_location,
            storage_timing: self.storage_metrics.timing_header,
        };

        let _ = api_client.send_metrics(workspace, metrics).await;
    }
}

impl SaveMetrics {
    pub async fn send(self, api_client: &ApiClient, workspace: &str) {
        OperationMetrics::from(self)
            .send(api_client, workspace)
            .await;
    }
}

impl RestoreMetrics {
    pub async fn send(self, api_client: &ApiClient, workspace: &str) {
        OperationMetrics::from(self)
            .send(api_client, workspace)
            .await;
    }
}
