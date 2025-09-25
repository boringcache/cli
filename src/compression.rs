use anyhow::{Context, Result};
use std::env;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompressionBackend {
    Lz4,
    Zstd,
}

#[derive(Debug)]
enum CompressionDecision {
    FavorZstd(String),
    FavorLz4(String),
}

#[derive(Debug, Clone, Copy)]
pub enum UsagePattern {
    Distribution,

    TemporaryCache,

    NetworkTransfer,

    LongTermStorage,
}

impl CompressionBackend {
    pub fn select() -> Self {
        if let Ok(backend) = env::var("BORINGCACHE_COMPRESSION") {
            match backend.to_lowercase().as_str() {
                "lz4" => return CompressionBackend::Lz4,
                "zstd" => return CompressionBackend::Zstd,
                _ => {}
            }
        }

        if env::var("BORINGCACHE_OPTIMIZE_FOR").unwrap_or_default() == "upload" {
            return CompressionBackend::Lz4;
        }

        if env::var("BORINGCACHE_NETWORK_TYPE").unwrap_or_default() == "datacenter" {
            return CompressionBackend::Lz4;
        }

        let _system = crate::platform::SystemResources::detect();

        if (_system.is_high_performance()
            && _system.cpu_cores >= 6
            && _system.available_memory_gb >= 8.0)
            || (_system.cpu_cores >= 4 && _system.available_memory_gb >= 4.0)
        {
            CompressionBackend::Zstd
        } else {
            CompressionBackend::Lz4
        }
    }

    pub fn select_for_size_and_pattern(data_size: usize, usage_pattern: UsagePattern) -> Self {
        if let Ok(backend) = env::var("BORINGCACHE_COMPRESSION") {
            match backend.to_lowercase().as_str() {
                "lz4" => return CompressionBackend::Lz4,
                "zstd" => return CompressionBackend::Zstd,
                _ => {}
            }
        }

        match usage_pattern {
            UsagePattern::Distribution => {
                if data_size > 10 * 1024 * 1024 {
                    CompressionBackend::Zstd
                } else {
                    CompressionBackend::Lz4
                }
            }

            UsagePattern::TemporaryCache => CompressionBackend::Lz4,

            UsagePattern::NetworkTransfer => {
                if data_size > 100 * 1024 * 1024 {
                    CompressionBackend::Zstd
                } else {
                    CompressionBackend::Lz4
                }
            }

            UsagePattern::LongTermStorage => {
                if data_size > 50 * 1024 * 1024 {
                    CompressionBackend::Zstd
                } else {
                    Self::select()
                }
            }
        }
    }

    pub fn select_intelligent(
        data_size: usize,
        file_count: u32,
        system: &crate::platform::SystemResources,
    ) -> Self {
        if let Ok(backend) = std::env::var("BORINGCACHE_COMPRESSION") {
            match backend.to_lowercase().as_str() {
                "lz4" => return CompressionBackend::Lz4,
                "zstd" => return CompressionBackend::Zstd,
                _ => {}
            }
        }

        match std::env::var("BORINGCACHE_OPTIMIZE_FOR")
            .unwrap_or_default()
            .as_str()
        {
            "speed" => return CompressionBackend::Lz4,
            "size" | "bandwidth" => return CompressionBackend::Zstd,
            "datacenter" => return CompressionBackend::Lz4,
            _ => {}
        }

        let size_mb = data_size as f64 / (1024.0 * 1024.0);
        let is_ci = std::env::var("CI").is_ok() || std::env::var("GITHUB_ACTIONS").is_ok();
        let is_container = std::path::Path::new("/.dockerenv").exists()
            || std::env::var("KUBERNETES_SERVICE_HOST").is_ok();

        match Self::analyze_context(size_mb, file_count, system, is_ci, is_container) {
            CompressionDecision::FavorZstd(_reason) => CompressionBackend::Zstd,
            CompressionDecision::FavorLz4(_reason) => CompressionBackend::Lz4,
        }
    }

    fn analyze_context(
        size_mb: f64,
        file_count: u32,
        system: &crate::platform::SystemResources,
        is_ci: bool,
        is_container: bool,
    ) -> CompressionDecision {
        if system.cpu_cores < 4 {
            return CompressionDecision::FavorLz4(format!(
                "limited CPU resources ({} cores)",
                system.cpu_cores
            ));
        }

        if is_container && (system.available_memory_gb < 4.0 || system.cpu_cores < 4) {
            return CompressionDecision::FavorLz4("container with limited resources".to_string());
        }

        if system.cpu_load_percent > 95.0 {
            return CompressionDecision::FavorLz4(format!(
                "extremely high CPU load ({:.1}%)",
                system.cpu_load_percent
            ));
        }

        if size_mb > 500.0 && system.cpu_cores >= 4 {
            return CompressionDecision::FavorZstd(format!(
                "large archive ({:.1}MB) with sufficient CPU ({} cores)",
                size_mb, system.cpu_cores
            ));
        }

        if system.cpu_cores >= 6 && size_mb > 100.0 {
            return CompressionDecision::FavorZstd(format!(
                "medium-large archive ({:.1}MB) with capable CPU ({} cores)",
                size_mb, system.cpu_cores
            ));
        }

        if system.is_high_performance() && size_mb > 50.0 {
            return CompressionDecision::FavorZstd(format!(
                "high-performance system with archive ({size_mb:.1}MB)"
            ));
        }

        if is_ci && size_mb > 100.0 && system.cpu_cores >= 4 {
            return CompressionDecision::FavorZstd(format!(
                "CI environment with large package ({:.1}MB, {} cores available)",
                size_mb, system.cpu_cores
            ));
        }

        if file_count > 5000 && system.cpu_cores >= 6 && size_mb > 50.0 {
            return CompressionDecision::FavorZstd(format!(
                "many small files ({} files, {:.1}MB) on capable system ({} cores)",
                file_count, size_mb, system.cpu_cores
            ));
        }

        if size_mb < 50.0 {
            return CompressionDecision::FavorLz4("small archive prioritizes speed".to_string());
        }

        CompressionDecision::FavorLz4("default speed-first strategy".to_string())
    }

    pub fn name(&self) -> &'static str {
        match self {
            CompressionBackend::Lz4 => "lz4",
            CompressionBackend::Zstd => "zstd",
        }
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            CompressionBackend::Lz4 => {
                use std::io::Write;
                let mut output = Vec::new();
                let mut encoder = lz4_flex::frame::FrameEncoder::new(&mut output);
                encoder.write_all(data)?;
                encoder.finish()?;
                Ok(output)
            }
            CompressionBackend::Zstd => {
                let compression_level = Self::adaptive_compression_level();
                let mut encoder = zstd::stream::Encoder::new(
                    Vec::with_capacity(data.len() / 2),
                    compression_level,
                )?;
                encoder.include_checksum(false)?;
                encoder.window_log(20)?;
                let mut reader = data;
                std::io::copy(&mut reader, &mut encoder)?;
                encoder.finish().context("Failed to compress with zstd")
            }
        }
    }

    fn adaptive_compression_level() -> i32 {
        if let Ok(level) = env::var("BORINGCACHE_ZSTD_LEVEL") {
            if let Ok(l) = level.parse::<i32>() {
                return l.clamp(1, 22);
            }
        }

        let system = crate::platform::SystemResources::detect();

        match (
            system.cpu_cores,
            system.available_memory_gb,
            system.is_high_performance(),
        ) {
            (cores, memory, true) if cores >= 16 && memory >= 32.0 => 6,
            (cores, memory, true) if cores >= 8 && memory >= 16.0 => 4,
            (cores, _, _) if cores >= 4 => 2,
            _ => 1,
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            CompressionBackend::Lz4 => {
                use std::io::{Cursor, Read};

                let cursor = Cursor::new(data);
                let mut decoder = lz4_flex::frame::FrameDecoder::new(cursor);
                let mut decompressed = Vec::new();

                decoder.read_to_end(&mut decompressed)?;
                Ok(decompressed)
            }
            CompressionBackend::Zstd => {
                let mut decoder = zstd::stream::Decoder::new(data)?;
                let mut decompressed = Vec::new();
                std::io::Read::read_to_end(&mut decoder, &mut decompressed)?;
                Ok(decompressed)
            }
        }
    }
}

pub fn compress_stream<R: std::io::Read, W: std::io::Write>(
    backend: CompressionBackend,
    reader: R,
    writer: W,
) -> Result<()> {
    match backend {
        CompressionBackend::Lz4 => {
            let mut encoder = lz4_flex::frame::FrameEncoder::new(writer);
            std::io::copy(&mut std::io::BufReader::new(reader), &mut encoder)?;
            encoder.finish()?;
        }
        CompressionBackend::Zstd => {
            let level = CompressionBackend::adaptive_compression_level();
            let mut encoder = zstd::stream::Encoder::new(writer, level)?;
            encoder.include_checksum(false)?;
            std::io::copy(&mut std::io::BufReader::new(reader), &mut encoder)?;
            encoder.finish()?;
        }
    }
    Ok(())
}

pub fn decompress_stream<R: std::io::Read, W: std::io::Write>(
    backend: CompressionBackend,
    reader: R,
    writer: W,
) -> Result<()> {
    match backend {
        CompressionBackend::Lz4 => {
            let mut decoder = lz4_flex::frame::FrameDecoder::new(reader);
            std::io::copy(&mut decoder, &mut std::io::BufWriter::new(writer))?;
        }
        CompressionBackend::Zstd => {
            let mut decoder = zstd::stream::Decoder::new(reader)?;
            std::io::copy(&mut decoder, &mut std::io::BufWriter::new(writer))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usage_pattern_selection() {
        std::env::remove_var("BORINGCACHE_COMPRESSION");

        let backend = CompressionBackend::select_for_size_and_pattern(
            200 * 1024 * 1024,
            UsagePattern::Distribution,
        );
        assert_eq!(backend, CompressionBackend::Zstd);

        let backend = CompressionBackend::select_for_size_and_pattern(
            200 * 1024 * 1024,
            UsagePattern::TemporaryCache,
        );
        assert_eq!(backend, CompressionBackend::Lz4);
    }

    #[test]
    fn test_compression_round_trip() {
        let data = b"Hello, World! This is a test of compression backends with streaming.";

        for backend in [CompressionBackend::Lz4, CompressionBackend::Zstd] {
            let compressed = backend.compress(data).unwrap();
            let decompressed = backend.decompress(&compressed).unwrap();
            assert_eq!(data, &decompressed[..]);
        }
    }

    #[test]
    fn test_stream_compression() {
        use std::io::Cursor;

        let data = b"Hello, World! This is a test of streaming compression.";

        for backend in [CompressionBackend::Lz4, CompressionBackend::Zstd] {
            let mut compressed = Vec::new();
            compress_stream(backend, Cursor::new(data), &mut compressed).unwrap();

            let mut decompressed = Vec::new();
            decompress_stream(backend, Cursor::new(&compressed), &mut decompressed).unwrap();

            assert_eq!(data, &decompressed[..]);
        }
    }

    #[test]
    fn test_intelligent_selection() {
        use crate::platform::{DiskType, MemoryStrategy, SystemResources};

        let high_perf_system = SystemResources {
            cpu_cores: 16,
            available_memory_gb: 32.0,
            cpu_load_percent: 30.0,
            max_parallel_chunks: 8,
            memory_strategy: MemoryStrategy::UltraAggressive,
            disk_type: DiskType::NvmeSsd,
            disk_speed_estimate_mb_s: 2000.0,
        };

        let low_perf_system = SystemResources {
            cpu_cores: 2,
            available_memory_gb: 2.0,
            cpu_load_percent: 80.0,
            max_parallel_chunks: 2,
            memory_strategy: MemoryStrategy::Balanced,
            disk_type: DiskType::SataSsd,
            disk_speed_estimate_mb_s: 300.0,
        };

        let backend =
            CompressionBackend::select_intelligent(2_000_000_000, 1000, &high_perf_system);
        assert_eq!(backend, CompressionBackend::Zstd);

        let backend = CompressionBackend::select_intelligent(10_000_000, 100, &high_perf_system);
        assert_eq!(backend, CompressionBackend::Lz4);

        let backend = CompressionBackend::select_intelligent(200_000_000, 1000, &low_perf_system);
        assert_eq!(backend, CompressionBackend::Lz4);

        let original_compression = std::env::var("BORINGCACHE_COMPRESSION").ok();
        let original_optimize_for = std::env::var("BORINGCACHE_OPTIMIZE_FOR").ok();
        let original_ci = std::env::var("CI").ok();
        let original_github_actions = std::env::var("GITHUB_ACTIONS").ok();

        std::env::remove_var("BORINGCACHE_OPTIMIZE_FOR");
        std::env::remove_var("CI");
        std::env::remove_var("GITHUB_ACTIONS");

        std::env::set_var("BORINGCACHE_COMPRESSION", "zstd");
        let backend = CompressionBackend::select_intelligent(1000, 10, &low_perf_system);
        assert_eq!(backend, CompressionBackend::Zstd);

        match original_compression {
            Some(val) => std::env::set_var("BORINGCACHE_COMPRESSION", val),
            None => std::env::remove_var("BORINGCACHE_COMPRESSION"),
        }
        match original_optimize_for {
            Some(val) => std::env::set_var("BORINGCACHE_OPTIMIZE_FOR", val),
            None => std::env::remove_var("BORINGCACHE_OPTIMIZE_FOR"),
        }
        match original_ci {
            Some(val) => std::env::set_var("CI", val),
            None => std::env::remove_var("CI"),
        }
        match original_github_actions {
            Some(val) => std::env::set_var("GITHUB_ACTIONS", val),
            None => std::env::remove_var("GITHUB_ACTIONS"),
        }
    }

    #[test]
    fn test_intelligent_selection_comprehensive() {
        use crate::platform::{DiskType, MemoryStrategy, SystemResources};

        std::env::remove_var("BORINGCACHE_COMPRESSION");
        std::env::remove_var("BORINGCACHE_OPTIMIZE_FOR");
        std::env::remove_var("CI");
        std::env::remove_var("GITHUB_ACTIONS");

        let high_perf = SystemResources {
            cpu_cores: 16,
            available_memory_gb: 32.0,
            cpu_load_percent: 30.0,
            max_parallel_chunks: 8,
            memory_strategy: MemoryStrategy::UltraAggressive,
            disk_type: DiskType::NvmeSsd,
            disk_speed_estimate_mb_s: 2000.0,
        };

        let mid_perf = SystemResources {
            cpu_cores: 8,
            available_memory_gb: 16.0,
            cpu_load_percent: 50.0,
            max_parallel_chunks: 4,
            memory_strategy: MemoryStrategy::Aggressive,
            disk_type: DiskType::SataSsd,
            disk_speed_estimate_mb_s: 500.0,
        };

        let low_perf = SystemResources {
            cpu_cores: 2,
            available_memory_gb: 2.0,
            cpu_load_percent: 80.0,
            max_parallel_chunks: 1,
            memory_strategy: MemoryStrategy::Balanced,
            disk_type: DiskType::SataSsd,
            disk_speed_estimate_mb_s: 300.0,
        };

        assert_eq!(
            CompressionBackend::select_intelligent(2_000_000_000, 1000, &high_perf),
            CompressionBackend::Zstd
        );

        assert_eq!(
            CompressionBackend::select_intelligent(669_000_000, 50000, &high_perf),
            CompressionBackend::Zstd
        );

        assert_eq!(
            CompressionBackend::select_intelligent(669_000_000, 50000, &low_perf),
            CompressionBackend::Lz4
        );

        assert_eq!(
            CompressionBackend::select_intelligent(10_000_000, 100, &high_perf),
            CompressionBackend::Lz4
        );

        assert_eq!(
            CompressionBackend::select_intelligent(100_000_000, 10000, &mid_perf),
            CompressionBackend::Zstd
        );

        std::env::set_var("CI", "true");
        assert_eq!(
            CompressionBackend::select_intelligent(150_000_000, 1000, &mid_perf),
            CompressionBackend::Zstd
        );
        std::env::remove_var("CI");

        std::env::set_var("BORINGCACHE_OPTIMIZE_FOR", "speed");
        assert_eq!(
            CompressionBackend::select_intelligent(2_000_000_000, 1000, &high_perf),
            CompressionBackend::Lz4
        );
        std::env::remove_var("BORINGCACHE_OPTIMIZE_FOR");

        std::env::set_var("BORINGCACHE_OPTIMIZE_FOR", "bandwidth");
        assert_eq!(
            CompressionBackend::select_intelligent(1000, 1, &low_perf),
            CompressionBackend::Zstd
        );
        std::env::remove_var("BORINGCACHE_OPTIMIZE_FOR");
    }
}
