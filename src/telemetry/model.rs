use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryData {
    pub operation_type: String,
    pub cache_path: String,
    pub manifest_root_digest: String,
    pub system_metrics: SystemMetrics,
    pub performance_metrics: PerformanceMetrics,
    pub compression_metrics: CompressionMetrics,
    pub timing_metrics: TimingMetrics,
    pub network_metrics: NetworkMetrics,
    pub size_metrics: SizeMetrics,
    pub storage_metrics: StorageMetrics,
    pub error_message: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_cores: u32,
    pub cpu_load_percent: f32,
    pub total_memory_gb: f64,
    pub available_memory_gb: f64,
    pub memory_strategy: String,
    pub disk_type: String,
    pub disk_speed_estimate_mb_s: f64,
    pub concurrent_operations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub buffer_size_mb: u32,
    pub part_size_mb: u32,
    pub concurrency_level: u32,
    pub streaming_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionMetrics {
    pub algorithm: String,
    pub level: u32,
    pub threads: u32,
    pub benchmark_throughput_mb_s: Option<f64>,
    pub benchmark_ratio: Option<f64>,
    pub actual_ratio: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingMetrics {
    pub total_duration_ms: u64,
    pub archive_duration_ms: Option<u64>,
    pub compression_duration_ms: Option<u64>,
    pub upload_duration_ms: Option<u64>,
    pub download_duration_ms: Option<u64>,
    pub extraction_duration_ms: Option<u64>,
    pub confirm_duration_ms: Option<u64>,
    pub predicted_time_ms: Option<u64>,
    pub prediction_accuracy: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub upload_speed_mb_s: Option<f64>,
    pub download_speed_mb_s: Option<f64>,
    pub bandwidth_probe_mb_s: Option<f64>,
    pub multipart_threshold_mb: Option<u64>,
    pub part_count: Option<u32>,
    pub retry_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeMetrics {
    pub file_count: Option<u32>,
    pub uncompressed_size: Option<u64>,
    pub compressed_size: Option<u64>,
    pub transfer_size: Option<u64>,
    pub cache_efficiency: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageMetrics {
    pub region: Option<String>,

    pub cache_status: Option<String>,

    pub block_location: Option<String>,

    pub timing_header: Option<String>,
}

impl StorageMetrics {
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> Self {
        let region = headers
            .get("x-tigris-served-from")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let timing_header = headers
            .get("server-timing")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let (cache_status, block_location) = timing_header
            .as_ref()
            .map(|h| Self::parse_server_timing(h))
            .unwrap_or((None, None));

        Self {
            region,
            cache_status,
            block_location,
            timing_header,
        }
    }

    fn parse_server_timing(header: &str) -> (Option<String>, Option<String>) {
        let mut cache_status = None;
        let mut block_location = None;

        for part in header.split(',') {
            let part = part.trim();
            if part.starts_with("cache;") {
                if let Some(desc_start) = part.find("desc=") {
                    let desc_value = &part[desc_start + 5..];
                    let end = desc_value.find(';').unwrap_or(desc_value.len());
                    cache_status = Some(desc_value[..end].to_string());
                }
            } else if part.starts_with("block;")
                && let Some(desc_start) = part.find("desc=")
            {
                let desc_value = &part[desc_start + 5..];
                let end = desc_value.find(';').unwrap_or(desc_value.len());
                block_location = Some(desc_value[..end].to_string());
            }
        }

        (cache_status, block_location)
    }
}
