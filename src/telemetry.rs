use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

use crate::api::ApiClient;
use crate::platform::SystemResources;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryData {
    pub operation_type: String,
    pub cache_path: String,
    pub content_hash: String,
    pub system_metrics: SystemMetrics,
    pub performance_metrics: PerformanceMetrics,
    pub compression_metrics: CompressionMetrics,
    pub timing_metrics: TimingMetrics,
    pub network_metrics: NetworkMetrics,
    pub size_metrics: SizeMetrics,
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

pub struct TelemetryCollector {
    start_time: SystemTime,
    system_resources: &'static SystemResources,
    operation_type: String,
    cache_path: String,
    content_hash: String,
    predicted_time_ms: Option<u64>,
    error_message: Option<String>,

    timing_data: TimingData,
    performance_data: PerformanceData,
    compression_data: CompressionData,
    network_data: NetworkData,
    size_data: SizeData,
}

#[derive(Default)]
struct TimingData {
    archive_start: Option<SystemTime>,
    upload_start: Option<SystemTime>,
    download_start: Option<SystemTime>,
    extraction_start: Option<SystemTime>,

    archive_duration: Option<Duration>,
    compression_duration: Option<Duration>,
    upload_duration: Option<Duration>,
    download_duration: Option<Duration>,
    extraction_duration: Option<Duration>,
    confirm_duration: Option<Duration>,
}

#[derive(Default)]
struct PerformanceData {
    buffer_size_mb: u32,
    part_size_mb: u32,
    concurrency_level: u32,
    streaming_enabled: bool,
}

#[derive(Default)]
struct CompressionData {
    algorithm: String,
    level: u32,
    threads: u32,
}

#[derive(Default)]
struct NetworkData {
    upload_speed_mb_s: Option<f64>,
    download_speed_mb_s: Option<f64>,
    bandwidth_probe_mb_s: Option<f64>,
    multipart_threshold_mb: Option<u64>,
    part_count: Option<u32>,
    retry_count: Option<u32>,
}

#[derive(Default)]
struct SizeData {
    file_count: Option<u32>,
    uncompressed_size: Option<u64>,
    compressed_size: Option<u64>,
    transfer_size: Option<u64>,
}

impl TelemetryCollector {
    pub fn new(operation_type: String, cache_path: String, content_hash: String) -> Self {
        Self {
            start_time: SystemTime::now(),
            system_resources: SystemResources::detect(),
            operation_type,
            cache_path,
            content_hash,
            predicted_time_ms: None,
            error_message: None,

            timing_data: TimingData::default(),
            performance_data: PerformanceData::default(),
            compression_data: CompressionData::default(),
            network_data: NetworkData::default(),
            size_data: SizeData::default(),
        }
    }

    pub fn set_compression_settings(&mut self, algorithm: String, level: u32, threads: u32) {
        self.compression_data.algorithm = algorithm;
        self.compression_data.level = level;
        self.compression_data.threads = threads;
    }

    pub fn set_size_data(
        &mut self,
        file_count: Option<u32>,
        uncompressed: Option<u64>,
        compressed: Option<u64>,
        transfer: Option<u64>,
    ) {
        self.size_data.file_count = file_count;
        self.size_data.uncompressed_size = uncompressed;
        self.size_data.compressed_size = compressed;
        self.size_data.transfer_size = transfer;
    }

    pub fn set_network_data(
        &mut self,
        upload_speed: Option<f64>,
        download_speed: Option<f64>,
        bandwidth_probe: Option<f64>,
        threshold_mb: Option<u64>,
        parts: Option<u32>,
        retries: Option<u32>,
    ) {
        self.network_data.upload_speed_mb_s = upload_speed;
        self.network_data.download_speed_mb_s = download_speed;
        self.network_data.bandwidth_probe_mb_s = bandwidth_probe;
        self.network_data.multipart_threshold_mb = threshold_mb;
        self.network_data.part_count = parts;
        self.network_data.retry_count = retries;
    }

    pub fn start_archive_timing(&mut self) {
        self.timing_data.archive_start = Some(SystemTime::now());
    }

    pub fn end_archive_timing(&mut self) {
        if let Some(start) = self.timing_data.archive_start {
            self.timing_data.archive_duration = start.elapsed().ok();
        }
    }

    pub fn start_upload_timing(&mut self) {
        self.timing_data.upload_start = Some(SystemTime::now());
    }

    pub fn end_upload_timing(&mut self) {
        if let Some(start) = self.timing_data.upload_start {
            self.timing_data.upload_duration = start.elapsed().ok();
        }
    }

    pub fn start_download_timing(&mut self) {
        self.timing_data.download_start = Some(SystemTime::now());
    }

    pub fn end_download_timing(&mut self) {
        if let Some(start) = self.timing_data.download_start {
            self.timing_data.download_duration = start.elapsed().ok();
        }
    }

    pub fn start_extraction_timing(&mut self) {
        self.timing_data.extraction_start = Some(SystemTime::now());
    }

    pub fn end_extraction_timing(&mut self) {
        if let Some(start) = self.timing_data.extraction_start {
            self.timing_data.extraction_duration = start.elapsed().ok();
        }
    }

    pub fn finalize(self) -> TelemetryData {
        let total_duration = self.start_time.elapsed().unwrap_or_default();
        let total_ms = total_duration.as_millis() as u64;

        let prediction_accuracy = self
            .predicted_time_ms
            .map(|predicted| (predicted as f64 - total_ms as f64).abs() / predicted as f64);

        let actual_compression_ratio = match (
            self.size_data.uncompressed_size,
            self.size_data.compressed_size,
        ) {
            (Some(uncomp), Some(comp)) if comp > 0 => Some(uncomp as f64 / comp as f64),
            _ => None,
        };

        let cache_efficiency = match (
            self.size_data.uncompressed_size,
            self.size_data.transfer_size,
        ) {
            (Some(orig), Some(transfer)) if transfer > 0 => Some(orig as f64 / transfer as f64),
            _ => None,
        };

        TelemetryData {
            operation_type: self.operation_type,
            cache_path: self.cache_path,
            content_hash: self.content_hash,

            system_metrics: SystemMetrics {
                cpu_cores: self.system_resources.cpu_cores as u32,
                cpu_load_percent: self.system_resources.cpu_load_percent,
                total_memory_gb: self.system_resources.available_memory_gb * 1.25,
                available_memory_gb: self.system_resources.available_memory_gb,
                memory_strategy: format!("{:?}", self.system_resources.memory_strategy),
                disk_type: format!("{:?}", self.system_resources.disk_type),
                disk_speed_estimate_mb_s: self.system_resources.disk_speed_estimate_mb_s,
                concurrent_operations: self.performance_data.concurrency_level,
            },

            performance_metrics: PerformanceMetrics {
                buffer_size_mb: self.performance_data.buffer_size_mb,
                part_size_mb: self.performance_data.part_size_mb,
                concurrency_level: self.performance_data.concurrency_level,
                streaming_enabled: self.performance_data.streaming_enabled,
            },

            compression_metrics: CompressionMetrics {
                algorithm: self.compression_data.algorithm,
                level: self.compression_data.level,
                threads: self.compression_data.threads,
                benchmark_throughput_mb_s: None,
                benchmark_ratio: None,
                actual_ratio: actual_compression_ratio,
            },

            timing_metrics: TimingMetrics {
                total_duration_ms: total_ms,
                archive_duration_ms: self
                    .timing_data
                    .archive_duration
                    .map(|d| d.as_millis() as u64),
                compression_duration_ms: self
                    .timing_data
                    .compression_duration
                    .map(|d| d.as_millis() as u64),
                upload_duration_ms: self
                    .timing_data
                    .upload_duration
                    .map(|d| d.as_millis() as u64),
                download_duration_ms: self
                    .timing_data
                    .download_duration
                    .map(|d| d.as_millis() as u64),
                extraction_duration_ms: self
                    .timing_data
                    .extraction_duration
                    .map(|d| d.as_millis() as u64),
                confirm_duration_ms: self
                    .timing_data
                    .confirm_duration
                    .map(|d| d.as_millis() as u64),
                predicted_time_ms: self.predicted_time_ms,
                prediction_accuracy,
            },

            network_metrics: NetworkMetrics {
                upload_speed_mb_s: self.network_data.upload_speed_mb_s,
                download_speed_mb_s: self.network_data.download_speed_mb_s,
                bandwidth_probe_mb_s: self.network_data.bandwidth_probe_mb_s,
                multipart_threshold_mb: self.network_data.multipart_threshold_mb,
                part_count: self.network_data.part_count,
                retry_count: self.network_data.retry_count,
            },

            size_metrics: SizeMetrics {
                file_count: self.size_data.file_count,
                uncompressed_size: self.size_data.uncompressed_size,
                compressed_size: self.size_data.compressed_size,
                transfer_size: self.size_data.transfer_size,
                cache_efficiency,
            },

            error_message: self.error_message,
            timestamp: Utc::now(),
        }
    }

    pub async fn submit_telemetry(
        api_client: &ApiClient,
        workspace: &str,
        telemetry: &TelemetryData,
    ) -> Result<()> {
        if std::env::var("BORINGCACHE_TELEMETRY_DISABLED").is_ok() {
            return Ok(());
        }

        log_telemetry_debug(telemetry);

        let tags = crate::ci_detection::build_tags_string();

        let metrics = crate::api::MetricsParams {
            operation_type: telemetry.operation_type.clone(),
            cache_path: Some(telemetry.cache_path.clone()),
            content_hash: Some(telemetry.content_hash.clone()),
            total_duration: telemetry.timing_metrics.total_duration_ms,

            archive_duration: telemetry.timing_metrics.archive_duration_ms,
            upload_duration: telemetry.timing_metrics.upload_duration_ms,
            download_duration: telemetry.timing_metrics.download_duration_ms,
            extract_duration: telemetry.timing_metrics.extraction_duration_ms,
            confirm_duration: telemetry.timing_metrics.confirm_duration_ms,

            uncompressed_size: telemetry.size_metrics.uncompressed_size,
            compressed_size: telemetry.size_metrics.compressed_size,
            compression_ratio: telemetry.compression_metrics.actual_ratio,
            file_count: telemetry.size_metrics.file_count,
            transfer_size: telemetry.size_metrics.transfer_size,
            cache_efficiency: telemetry.size_metrics.cache_efficiency,

            upload_speed_mbps: telemetry.network_metrics.upload_speed_mb_s,
            download_speed_mbps: telemetry.network_metrics.download_speed_mb_s,
            bandwidth_probe_mb_s: telemetry.network_metrics.bandwidth_probe_mb_s,
            multipart_threshold_mb: telemetry
                .network_metrics
                .multipart_threshold_mb
                .map(|v| v as u32),
            part_count: telemetry.network_metrics.part_count,
            retry_count: telemetry.network_metrics.retry_count,

            cpu_cores: Some(telemetry.system_metrics.cpu_cores),
            cpu_load_percent: Some(telemetry.system_metrics.cpu_load_percent as f64),
            total_memory_gb: Some(telemetry.system_metrics.total_memory_gb),
            available_memory_gb: Some(telemetry.system_metrics.available_memory_gb),
            memory_strategy: Some(telemetry.system_metrics.memory_strategy.clone()),
            disk_type: Some(telemetry.system_metrics.disk_type.clone()),
            disk_speed_estimate_mb_s: Some(telemetry.system_metrics.disk_speed_estimate_mb_s),
            concurrent_operations: Some(telemetry.system_metrics.concurrent_operations),

            buffer_size_mb: Some(telemetry.performance_metrics.buffer_size_mb),
            part_size_mb: Some(telemetry.performance_metrics.part_size_mb),
            concurrency_level: Some(telemetry.performance_metrics.concurrency_level),
            streaming_enabled: Some(telemetry.performance_metrics.streaming_enabled),

            compression_algorithm: Some(telemetry.compression_metrics.algorithm.clone()),
            compression_level: Some(telemetry.compression_metrics.level),
            compression_threads: Some(telemetry.compression_metrics.threads),
            benchmark_throughput_mb_s: telemetry.compression_metrics.benchmark_throughput_mb_s,
            benchmark_compression_ratio: telemetry.compression_metrics.benchmark_ratio,
            compression_duration: telemetry.timing_metrics.compression_duration_ms,

            predicted_time_ms: telemetry.timing_metrics.predicted_time_ms,
            prediction_accuracy: telemetry.timing_metrics.prediction_accuracy,

            cache_age_hours: None,
            error_message: telemetry.error_message.clone(),

            tags: Some(vec![tags.to_string()]),
        };

        match api_client.send_metrics(workspace, metrics).await {
            Ok(_) => Ok(()),
            Err(_e) => Ok(()),
        }
    }
}

pub fn log_telemetry_debug(telemetry: &TelemetryData) {
    if std::env::var("BORINGCACHE_DEBUG_TELEMETRY").is_ok() {
        let json = serde_json::to_string_pretty(telemetry).unwrap_or_default();
        eprintln!("=== TELEMETRY DEBUG ===\n{json}\n=====================");
    }
}
