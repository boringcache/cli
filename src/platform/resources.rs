use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct SystemResources {
    pub cpu_cores: usize,
    pub available_memory_gb: f64,
    pub cpu_load_percent: f32,
    pub max_parallel_chunks: usize,
    pub memory_strategy: MemoryStrategy,
    pub disk_type: DiskType,
    pub disk_speed_estimate_mb_s: f64,
}

#[derive(Debug, Clone)]
pub enum DiskType {
    SataSsd,
    NvmeSsd,
}

#[derive(Debug, Clone)]
pub enum MemoryStrategy {
    Balanced,
    Aggressive,
    UltraAggressive,
}

static SYSTEM_RESOURCES: OnceLock<SystemResources> = OnceLock::new();

impl SystemResources {
    pub fn detect() -> &'static Self {
        SYSTEM_RESOURCES.get_or_init(|| {
            let cpu_cores = num_cpus::get();
            let available_memory_gb = detect_available_memory_gb();
            let cpu_load_percent = detect_cpu_load();
            let (disk_type, disk_speed_estimate_mb_s) = detect_disk_type();

            let memory_strategy = if available_memory_gb >= 24.0 {
                MemoryStrategy::UltraAggressive
            } else if available_memory_gb >= 12.0 {
                MemoryStrategy::Aggressive
            } else {
                MemoryStrategy::Balanced
            };

            let base_chunks = match (cpu_cores, &memory_strategy) {
                (cores, MemoryStrategy::Balanced) => std::cmp::min(cores, 8),
                (cores, MemoryStrategy::Aggressive) => std::cmp::min(cores + 2, 12),
                (cores, MemoryStrategy::UltraAggressive) => std::cmp::min(cores + 4, 16),
            };

            let max_parallel_chunks = if cpu_load_percent > 80.0 {
                base_chunks / 2
            } else {
                base_chunks
            };

            SystemResources {
                cpu_cores,
                available_memory_gb,
                cpu_load_percent,
                max_parallel_chunks,
                memory_strategy,
                disk_type,
                disk_speed_estimate_mb_s,
            }
        })
    }

    pub fn extraction_buffer_size(&self) -> usize {
        match self.memory_strategy {
            MemoryStrategy::Balanced => 64 * 1024 * 1024,
            MemoryStrategy::Aggressive => 256 * 1024 * 1024,
            MemoryStrategy::UltraAggressive => 512 * 1024 * 1024,
        }
    }

    pub fn multipart_threshold(&self) -> u64 {
        match self.memory_strategy {
            MemoryStrategy::Balanced => 2 * 1024 * 1024,
            MemoryStrategy::Aggressive => 1024 * 1024,
            MemoryStrategy::UltraAggressive => 512 * 1024,
        }
    }

    pub fn should_use_parallel_extraction(&self) -> bool {
        if std::env::var("CI").is_ok() || self.available_memory_gb < 4.0 {
            false
        } else {
            self.cpu_cores >= 2
        }
    }

    pub fn is_high_performance(&self) -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            self.available_memory_gb >= 8.0
                && self.cpu_cores >= 4
                && self.cpu_load_percent < 60.0
                && matches!(
                    self.memory_strategy,
                    MemoryStrategy::Aggressive | MemoryStrategy::UltraAggressive
                )
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    }

    pub fn recommended_download_concurrency(&self, is_ci: bool) -> usize {
        let mut concurrency = self.max_parallel_chunks.max(2);

        concurrency = if self.available_memory_gb < 4.0 {
            concurrency.min(2)
        } else if self.available_memory_gb < 8.0 {
            concurrency.min(4)
        } else {
            concurrency
        };

        concurrency = match self.disk_type {
            DiskType::NvmeSsd => concurrency.min(16),
            DiskType::SataSsd => concurrency.min(if is_ci { 8 } else { 4 }),
        };

        if self.cpu_load_percent > 75.0 && concurrency > 1 {
            concurrency -= 1;
        }

        if is_ci {
            let ci_cap = if self.available_memory_gb >= 12.0 {
                12
            } else if self.available_memory_gb >= 8.0 {
                8
            } else {
                4
            };
            concurrency = concurrency.min(ci_cap);
            if self.cpu_cores <= 2 {
                concurrency = concurrency.min(2);
            } else if matches!(self.disk_type, DiskType::NvmeSsd)
                && self.available_memory_gb >= 12.0
                && self.cpu_cores >= 4
            {
                concurrency = concurrency.max(12);
            }
        } else {
            let cpu_headroom = (self.cpu_cores.saturating_sub(1)).max(1);
            concurrency = concurrency.min(cpu_headroom * 2);
        }

        concurrency.clamp(1, 16)
    }

    pub fn recommended_proxy_download_concurrency(&self, is_ci: bool) -> usize {
        let mut concurrency = self.recommended_download_concurrency(is_ci);

        if is_ci && self.available_memory_gb >= 4.0 && self.cpu_load_percent <= 75.0 {
            // Registry-proxy warmup is dominated by storage request scheduling
            // and object reads. Do not let small CI CPU counts force a serial
            // prewarm path for thousands of small/medium cache blobs.
            let io_floor = if self.available_memory_gb >= 8.0 {
                10
            } else {
                8
            };
            concurrency = concurrency.max(io_floor);
        }

        if self.cpu_load_percent > 85.0 {
            concurrency = concurrency.min(4);
        }

        concurrency.clamp(1, 16)
    }

    pub fn recommended_proxy_prefetch_concurrency(&self, is_ci: bool) -> usize {
        let base = self.recommended_proxy_download_concurrency(is_ci);
        if !is_ci || self.cpu_load_percent > 75.0 || self.available_memory_gb < 4.0 {
            return base;
        }

        let ceiling = if matches!(self.disk_type, DiskType::NvmeSsd)
            && self.available_memory_gb >= 8.0
            && self.cpu_cores >= 4
        {
            100
        } else if self.available_memory_gb >= 4.0 && self.cpu_cores >= 2 {
            50
        } else {
            base
        };

        ceiling.max(base).clamp(1, 100)
    }
}

pub(crate) fn proxy_resource_pressure_high() -> bool {
    current_load_average_per_core().is_some_and(|load| load > 1.5)
        || current_available_memory_mb()
            .is_some_and(|available_mb| available_mb < proxy_min_free_memory_mb())
}

fn proxy_min_free_memory_mb() -> f64 {
    std::env::var("BORINGCACHE_PROXY_MIN_FREE_MB")
        .ok()
        .and_then(|value| value.trim().parse::<f64>().ok())
        .filter(|value| *value > 0.0)
        .unwrap_or(256.0)
}

fn current_load_average_per_core() -> Option<f64> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let mut loads = [0.0_f64; 3];
        // SAFETY: `loads` is a valid writable array with at least one slot, and
        // `getloadavg` is called with `nelem=1`, so libc writes within bounds.
        let loaded = unsafe { libc::getloadavg(loads.as_mut_ptr(), 1) };
        if loaded == 1 {
            return Some(loads[0] / num_cpus::get().max(1) as f64);
        }
    }

    None
}

fn current_available_memory_mb() -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
        for line in meminfo.lines() {
            if line.starts_with("MemAvailable:")
                && let Some(kb_str) = line.split_whitespace().nth(1)
                && let Ok(kb) = kb_str.parse::<u64>()
            {
                return Some(kb as f64 / 1024.0);
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    {
        let output = Command::new("vm_stat").output().ok()?;
        if !output.status.success() {
            return None;
        }
        let output = String::from_utf8(output.stdout).ok()?;
        let page_size = output
            .lines()
            .next()
            .and_then(|line| line.split("page size of ").nth(1))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(4096);
        let mut pages = 0u64;
        for line in output.lines() {
            if (line.starts_with("Pages free:")
                || line.starts_with("Pages inactive:")
                || line.starts_with("Pages speculative:"))
                && let Some(raw) = line.split(':').nth(1)
            {
                let cleaned = raw.trim().trim_end_matches('.').replace('.', "");
                if let Ok(count) = cleaned.parse::<u64>() {
                    pages = pages.saturating_add(count);
                }
            }
        }
        Some((pages.saturating_mul(page_size)) as f64 / (1024.0 * 1024.0))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

fn detect_available_memory_gb() -> f64 {
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("sysctl").args(["-n", "hw.memsize"]).output()
            && let Ok(mem_str) = String::from_utf8(output.stdout)
            && let Ok(mem_bytes) = mem_str.trim().parse::<u64>()
        {
            return mem_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            let mut mem_available = None;
            let mut mem_total = None;

            for line in meminfo.lines() {
                if line.starts_with("MemAvailable:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1)
                        && let Ok(kb) = kb_str.parse::<u64>()
                    {
                        mem_available = Some(kb as f64 / (1024.0 * 1024.0));
                    }
                } else if line.starts_with("MemTotal:")
                    && let Some(kb_str) = line.split_whitespace().nth(1)
                    && let Ok(kb) = kb_str.parse::<u64>()
                {
                    mem_total = Some(kb as f64 / (1024.0 * 1024.0));
                }
            }

            if let Some(available) = mem_available {
                return available;
            } else if let Some(total) = mem_total {
                return total * 0.7;
            }
        }
    }

    2.0
}

fn detect_cpu_load() -> f32 {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        if let Ok(output) = Command::new("uptime")
            .output()
            .map_err(|_| ())
            .and_then(|o| if o.status.success() { Ok(o) } else { Err(()) })
            && let Ok(uptime_str) = String::from_utf8(output.stdout)
        {
            let load_part = uptime_str
                .split("load averages:")
                .nth(1)
                .or_else(|| uptime_str.split("load average:").nth(1));

            if let Some(load_part) = load_part
                && let Some(first_load) = load_part.split_whitespace().next()
                && let Ok(load) = first_load.trim().parse::<f32>()
            {
                let cpu_cores = num_cpus::get() as f32;
                let cpu_load = (load / cpu_cores) * 100.0;
                return cpu_load.min(100.0);
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("wmic")
            .args(["cpu", "get", "loadpercentage", "/value"])
            .output()
            && let Ok(output_str) = String::from_utf8(output.stdout)
        {
            for line in output_str.lines() {
                if let Some(value) = line.strip_prefix("LoadPercentage=")
                    && let Ok(load) = value.trim().parse::<f32>()
                {
                    return load;
                }
            }
        }
    }

    50.0
}

fn detect_disk_type() -> (DiskType, f64) {
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("system_profiler")
            .args(["SPStorageDataType", "-json"])
            .output()
            && let Ok(json_str) = String::from_utf8(output.stdout)
            && (json_str.contains("SSD") || json_str.contains("Flash"))
        {
            if json_str.contains("NVMe") || json_str.contains("PCIe") {
                return (DiskType::NvmeSsd, 2000.0);
            } else {
                return (DiskType::SataSsd, 500.0);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(mounts) = std::fs::read_to_string("/proc/mounts")
            && let Some(line) = mounts.lines().find(|line| line.contains(" / "))
        {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(device) = parts.first() {
                let device_name = device.trim_start_matches("/dev/");

                if device_name.starts_with("nvme") {
                    return (DiskType::NvmeSsd, 2000.0);
                }

                let sys_path = format!("/sys/block/{}/queue/rotational", device_name);
                if let Ok(rotational) = std::fs::read_to_string(&sys_path)
                    && rotational.trim() == "0"
                {
                    return (DiskType::SataSsd, 500.0);
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("powershell")
            .args([
                "-Command",
                "Get-PhysicalDisk | Select-Object MediaType, BusType",
            ])
            .output()
            && let Ok(output_str) = String::from_utf8(output.stdout)
        {
            if output_str.contains("NVMe") || output_str.contains("PCIe") {
                return (DiskType::NvmeSsd, 2000.0);
            } else if output_str.contains("SSD") {
                return (DiskType::SataSsd, 500.0);
            }
        }
    }

    (DiskType::SataSsd, 500.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_resources_detection() {
        let resources = SystemResources::detect();
        assert!(resources.cpu_cores > 0);
        assert!(resources.available_memory_gb > 0.0);
        assert!(resources.max_parallel_chunks > 0);
        assert!(resources.disk_speed_estimate_mb_s > 0.0);
    }

    #[test]
    fn test_buffer_sizes() {
        let resources = SystemResources::detect();
        assert!(resources.extraction_buffer_size() > 0);
        assert!(resources.multipart_threshold() > 0);
    }

    #[test]
    fn recommended_download_concurrency_scales_up_on_capable_ci_runners() {
        let resources = SystemResources {
            cpu_cores: 4,
            available_memory_gb: 16.0,
            cpu_load_percent: 10.0,
            max_parallel_chunks: 8,
            memory_strategy: MemoryStrategy::Aggressive,
            disk_type: DiskType::NvmeSsd,
            disk_speed_estimate_mb_s: 2_000.0,
        };

        assert_eq!(resources.recommended_download_concurrency(true), 12);
    }

    #[test]
    fn recommended_download_concurrency_stays_conservative_on_small_ci_runners() {
        let resources = SystemResources {
            cpu_cores: 2,
            available_memory_gb: 3.5,
            cpu_load_percent: 10.0,
            max_parallel_chunks: 8,
            memory_strategy: MemoryStrategy::Balanced,
            disk_type: DiskType::SataSsd,
            disk_speed_estimate_mb_s: 500.0,
        };

        assert_eq!(resources.recommended_download_concurrency(true), 2);
    }

    #[test]
    fn proxy_download_concurrency_allows_ci_io_parallelism_on_two_core_runners() {
        let resources = SystemResources {
            cpu_cores: 2,
            available_memory_gb: 7.0,
            cpu_load_percent: 10.0,
            max_parallel_chunks: 8,
            memory_strategy: MemoryStrategy::Balanced,
            disk_type: DiskType::SataSsd,
            disk_speed_estimate_mb_s: 500.0,
        };

        assert_eq!(resources.recommended_download_concurrency(true), 2);
        assert_eq!(resources.recommended_proxy_download_concurrency(true), 8);
        assert_eq!(resources.recommended_proxy_prefetch_concurrency(true), 50);
    }

    #[test]
    fn proxy_download_concurrency_backs_off_when_runner_is_cpu_saturated() {
        let resources = SystemResources {
            cpu_cores: 4,
            available_memory_gb: 16.0,
            cpu_load_percent: 90.0,
            max_parallel_chunks: 8,
            memory_strategy: MemoryStrategy::Aggressive,
            disk_type: DiskType::NvmeSsd,
            disk_speed_estimate_mb_s: 2_000.0,
        };

        assert_eq!(resources.recommended_proxy_download_concurrency(true), 4);
        assert_eq!(resources.recommended_proxy_prefetch_concurrency(true), 4);
    }

    #[test]
    fn proxy_prefetch_concurrency_scales_for_capable_ci_runners() {
        let resources = SystemResources {
            cpu_cores: 4,
            available_memory_gb: 16.0,
            cpu_load_percent: 10.0,
            max_parallel_chunks: 8,
            memory_strategy: MemoryStrategy::Aggressive,
            disk_type: DiskType::NvmeSsd,
            disk_speed_estimate_mb_s: 2_000.0,
        };

        assert_eq!(resources.recommended_proxy_download_concurrency(true), 12);
        assert_eq!(resources.recommended_proxy_prefetch_concurrency(true), 100);
    }
}
