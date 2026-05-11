use crate::platform::resources::{DiskType, SystemResources};

const MIB: u64 = 1024 * 1024;
const LARGE_ARCHIVE_BYTES: u64 = 512 * MIB;
const DEFAULT_PARALLEL_DOWNLOAD_THRESHOLD: u64 = 50 * MIB;
const MIN_DOWNLOAD_PART_SIZE: u64 = 8 * MIB;
const MAX_DOWNLOAD_PART_SIZE: u64 = 64 * MIB;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchiveTransferPlan {
    pub mode: &'static str,
    pub profile: &'static str,
    pub reason: &'static str,
    pub concurrency: usize,
    pub part_size: Option<u64>,
    pub part_count: Option<u64>,
}

impl ArchiveTransferPlan {
    pub(crate) fn concurrency_level(&self) -> Option<u32> {
        Some(self.concurrency as u32).filter(|value| *value > 0)
    }

    pub(crate) fn part_size_mb(&self) -> Option<u32> {
        self.part_size.map(|bytes| bytes.div_ceil(MIB) as u32)
    }

    pub(crate) fn part_count(&self) -> Option<u32> {
        self.part_count.map(|count| count as u32)
    }
}

pub(crate) fn parallel_download_threshold() -> u64 {
    std::env::var("BORINGCACHE_ARCHIVE_PARALLEL_DOWNLOAD_THRESHOLD_MB")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(|value| value * MIB)
        .unwrap_or(DEFAULT_PARALLEL_DOWNLOAD_THRESHOLD)
}

pub(crate) fn plan_download(total_size: u64, range_supported: bool) -> ArchiveTransferPlan {
    if total_size < parallel_download_threshold() {
        return ArchiveTransferPlan {
            mode: "stream",
            profile: "small_archive_stream",
            reason: "archive below ranged download threshold",
            concurrency: 1,
            part_size: None,
            part_count: Some(1),
        };
    }

    if !range_supported {
        return ArchiveTransferPlan {
            mode: "stream",
            profile: "range_unavailable_stream",
            reason: "storage did not accept ranged reads",
            concurrency: 1,
            part_size: None,
            part_count: Some(1),
        };
    }

    let concurrency = archive_download_concurrency(total_size);
    let part_size = download_part_size(total_size, concurrency);
    let part_count = total_size.div_ceil(part_size);

    ArchiveTransferPlan {
        mode: "ranged",
        profile: if total_size >= LARGE_ARCHIVE_BYTES {
            "large_archive_byte_throughput"
        } else {
            "medium_archive_parallel"
        },
        reason: if std::env::var("BORINGCACHE_ARCHIVE_DOWNLOAD_CONCURRENCY").is_ok() {
            "explicit archive download concurrency"
        } else if std::env::var("CI").is_ok() && total_size >= LARGE_ARCHIVE_BYTES {
            "large archive on CI runner"
        } else {
            "parallel ranged archive download"
        },
        concurrency,
        part_size: Some(part_size),
        part_count: Some(part_count),
    }
}

pub(crate) fn plan_upload(total_size: u64, available_parts: usize) -> ArchiveTransferPlan {
    if available_parts <= 1 {
        return ArchiveTransferPlan {
            mode: "stream",
            profile: "single_archive_upload",
            reason: "single upload URL",
            concurrency: 1,
            part_size: None,
            part_count: Some(1),
        };
    }

    let concurrency = archive_upload_concurrency(total_size, available_parts);
    let part_size = total_size.div_ceil(available_parts as u64);

    ArchiveTransferPlan {
        mode: "multipart",
        profile: if total_size >= LARGE_ARCHIVE_BYTES {
            "large_archive_multipart"
        } else {
            "medium_archive_multipart"
        },
        reason: if std::env::var("BORINGCACHE_ARCHIVE_UPLOAD_CONCURRENCY").is_ok() {
            "explicit archive upload concurrency"
        } else if std::env::var("CI").is_ok() && total_size >= LARGE_ARCHIVE_BYTES {
            "large archive on CI runner"
        } else {
            "multipart archive upload"
        },
        concurrency,
        part_size: Some(part_size),
        part_count: Some(available_parts as u64),
    }
}

fn archive_download_concurrency(total_size: u64) -> usize {
    if let Some(value) = parse_concurrency_env("BORINGCACHE_ARCHIVE_DOWNLOAD_CONCURRENCY") {
        return value;
    }

    let resources = SystemResources::detect();
    let is_ci = std::env::var("CI").is_ok();
    let base = resources.recommended_download_concurrency(is_ci);

    if !is_ci || total_size < LARGE_ARCHIVE_BYTES {
        return base;
    }

    if resources.available_memory_gb < 4.0 || resources.cpu_load_percent > 85.0 {
        return base;
    }

    let large_archive_floor = match resources.disk_type {
        DiskType::NvmeSsd if resources.available_memory_gb >= 8.0 => 32,
        DiskType::NvmeSsd => 24,
        DiskType::SataSsd => 16,
    };

    base.max(large_archive_floor).clamp(1, 32)
}

fn archive_upload_concurrency(total_size: u64, available_parts: usize) -> usize {
    if let Some(value) = parse_concurrency_env("BORINGCACHE_ARCHIVE_UPLOAD_CONCURRENCY") {
        return value.min(available_parts.max(1));
    }

    let resources = SystemResources::detect();
    let is_ci = std::env::var("CI").is_ok();
    let mut concurrency = match resources.disk_type {
        DiskType::NvmeSsd => 6,
        DiskType::SataSsd => 4,
    };

    if is_ci && total_size >= LARGE_ARCHIVE_BYTES && resources.available_memory_gb >= 4.0 {
        concurrency = concurrency.max(10);
        if resources.available_memory_gb >= 8.0 && resources.cpu_load_percent <= 75.0 {
            concurrency = concurrency.max(12);
        }
    }

    if resources.cpu_load_percent > 85.0 {
        concurrency = concurrency.min(4);
    }

    concurrency.clamp(1, 12).min(available_parts.max(1))
}

fn download_part_size(total_size: u64, concurrency: usize) -> u64 {
    let target_parts = (concurrency * 3).max(8) as u64;
    (total_size / target_parts).clamp(MIN_DOWNLOAD_PART_SIZE, MAX_DOWNLOAD_PART_SIZE)
}

fn parse_concurrency_env(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.clamp(1, 256))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env;
    use std::ffi::OsString;

    struct EnvSnapshot {
        values: Vec<(&'static str, Option<OsString>)>,
    }

    impl EnvSnapshot {
        fn capture(keys: &[&'static str]) -> Self {
            Self {
                values: keys
                    .iter()
                    .map(|key| (*key, std::env::var_os(*key)))
                    .collect(),
            }
        }
    }

    impl Drop for EnvSnapshot {
        fn drop(&mut self) {
            for (key, value) in &self.values {
                if let Some(value) = value {
                    test_env::set_var(key, value);
                } else {
                    test_env::remove_var(key);
                }
            }
        }
    }

    #[test]
    fn small_archive_uses_streaming_download() {
        let _guard = test_env::lock();
        let _snapshot = EnvSnapshot::capture(&[
            "CI",
            "BORINGCACHE_ARCHIVE_DOWNLOAD_CONCURRENCY",
            "BORINGCACHE_ARCHIVE_PARALLEL_DOWNLOAD_THRESHOLD_MB",
        ]);
        test_env::remove_var("CI");
        test_env::remove_var("BORINGCACHE_ARCHIVE_DOWNLOAD_CONCURRENCY");
        test_env::remove_var("BORINGCACHE_ARCHIVE_PARALLEL_DOWNLOAD_THRESHOLD_MB");

        let plan = plan_download(10 * MIB, true);

        assert_eq!(plan.mode, "stream");
        assert_eq!(plan.profile, "small_archive_stream");
        assert_eq!(plan.concurrency, 1);
    }

    #[test]
    fn range_unavailable_uses_streaming_download() {
        let _guard = test_env::lock();
        let _snapshot = EnvSnapshot::capture(&[
            "CI",
            "BORINGCACHE_ARCHIVE_DOWNLOAD_CONCURRENCY",
            "BORINGCACHE_ARCHIVE_PARALLEL_DOWNLOAD_THRESHOLD_MB",
        ]);
        test_env::remove_var("CI");
        test_env::remove_var("BORINGCACHE_ARCHIVE_DOWNLOAD_CONCURRENCY");
        test_env::remove_var("BORINGCACHE_ARCHIVE_PARALLEL_DOWNLOAD_THRESHOLD_MB");

        let plan = plan_download(700 * MIB, false);

        assert_eq!(plan.mode, "stream");
        assert_eq!(plan.profile, "range_unavailable_stream");
        assert_eq!(plan.concurrency, 1);
    }

    #[test]
    fn explicit_download_concurrency_controls_large_archives() {
        let _guard = test_env::lock();
        let _snapshot = EnvSnapshot::capture(&["CI", "BORINGCACHE_ARCHIVE_DOWNLOAD_CONCURRENCY"]);
        test_env::set_var("CI", "1");
        test_env::set_var("BORINGCACHE_ARCHIVE_DOWNLOAD_CONCURRENCY", "24");

        let plan = plan_download(734 * MIB, true);

        assert_eq!(plan.mode, "ranged");
        assert_eq!(plan.concurrency, 24);
        assert_eq!(plan.profile, "large_archive_byte_throughput");
        assert!(plan.part_count.unwrap() > 1);
    }

    #[test]
    fn explicit_upload_concurrency_caps_to_available_parts() {
        let _guard = test_env::lock();
        let _snapshot = EnvSnapshot::capture(&["CI", "BORINGCACHE_ARCHIVE_UPLOAD_CONCURRENCY"]);
        test_env::set_var("CI", "1");
        test_env::set_var("BORINGCACHE_ARCHIVE_UPLOAD_CONCURRENCY", "20");

        let plan = plan_upload(734 * MIB, 15);

        assert_eq!(plan.mode, "multipart");
        assert_eq!(plan.concurrency, 15);
        assert_eq!(plan.part_count, Some(15));
    }
}
