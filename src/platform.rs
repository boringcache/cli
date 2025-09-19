use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Platform {
    pub os: String,
    pub arch: String,
    pub distro: Option<String>,
    pub version: Option<String>,
    pub glibc: Option<String>,
}

impl Platform {
    pub fn process_exists(pid: u32) -> bool {
        #[cfg(unix)]
        {
            match std::process::Command::new("kill")
                .arg("-0")
                .arg(pid.to_string())
                .output()
            {
                Ok(output) => output.status.success(),
                Err(_) => false,
            }
        }

        #[cfg(windows)]
        {
            match std::process::Command::new("tasklist")
                .arg("/FI")
                .arg(format!("PID eq {}", pid))
                .arg("/FO")
                .arg("CSV")
                .output()
            {
                Ok(output) => {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    output_str.lines().count() > 1
                }
                Err(_) => false,
            }
        }
    }

    pub fn detect() -> Result<Self> {
        let os = Self::detect_os();
        let arch = Self::detect_arch();
        let (distro, version) = Self::detect_distro_and_version();
        let glibc = Self::detect_glibc();

        Ok(Platform {
            os,
            arch,
            distro,
            version,
            glibc,
        })
    }

    fn detect_os() -> String {
        match std::env::consts::OS {
            "linux" => "linux".to_string(),
            "macos" => "macos".to_string(),
            "windows" => "windows".to_string(),
            other => other.to_string(),
        }
    }

    fn detect_arch() -> String {
        match std::env::consts::ARCH {
            "x86_64" => "x64".to_string(),
            "aarch64" => "arm64".to_string(),
            "arm" => "arm32".to_string(),
            other => other.to_string(),
        }
    }

    fn detect_distro_and_version() -> (Option<String>, Option<String>) {
        if cfg!(target_os = "linux") {
            Self::detect_linux_distro()
        } else if cfg!(target_os = "macos") {
            Self::detect_macos_version()
        } else {
            (None, None)
        }
    }

    #[cfg(target_os = "linux")]
    fn detect_linux_distro() -> (Option<String>, Option<String>) {
        if let Ok(contents) = std::fs::read_to_string("/etc/os-release") {
            let mut distro = None;
            let mut version = None;

            for line in contents.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    let value = value.trim_matches('"');
                    match key {
                        "ID" => distro = Some(value.to_string()),
                        "VERSION_ID" => version = Some(value.to_string()),
                        _ => {}
                    }
                }
            }

            return (distro, version);
        }

        if std::path::Path::new("/etc/ubuntu-release").exists() {
            return (Some("ubuntu".to_string()), None);
        }
        if std::path::Path::new("/etc/debian_version").exists() {
            return (Some("debian".to_string()), None);
        }
        if std::path::Path::new("/etc/redhat-release").exists() {
            return (Some("rhel".to_string()), None);
        }
        if std::path::Path::new("/etc/alpine-release").exists() {
            return (Some("alpine".to_string()), None);
        }
        if std::path::Path::new("/etc/arch-release").exists() {
            return (Some("arch".to_string()), None);
        }

        (None, None)
    }

    #[cfg(not(target_os = "linux"))]
    fn detect_linux_distro() -> (Option<String>, Option<String>) {
        (None, None)
    }

    #[cfg(target_os = "macos")]
    fn detect_macos_version() -> (Option<String>, Option<String>) {
        if let Ok(output) = Command::new("sw_vers").arg("-productVersion").output() {
            if let Ok(version_str) = String::from_utf8(output.stdout) {
                let version = version_str.trim();
                let major_version = version.split('.').next().unwrap_or(version);
                return (Some("darwin".to_string()), Some(major_version.to_string()));
            }
        }
        (Some("darwin".to_string()), None)
    }

    #[cfg(not(target_os = "macos"))]
    fn detect_macos_version() -> (Option<String>, Option<String>) {
        (None, None)
    }

    #[cfg(target_os = "linux")]
    fn detect_glibc() -> Option<String> {
        if let Ok(output) = Command::new("ldd").arg("--version").output() {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                for line in output_str.lines() {
                    if line.contains("GLIBC") || line.contains("GNU libc") {
                        if let Some(version_start) = line.rfind(' ') {
                            let version = &line[version_start + 1..];
                            if version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                                return Some(version.trim().to_string());
                            }
                        }
                    }
                }
            }
        }

        if let Ok(output) = Command::new("sh")
            .arg("-c")
            .arg("ldd /bin/ls | grep libc.so.6")
            .output()
        {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                if let Some(path_start) = output_str.find("/lib") {
                    if let Some(path_end) = output_str[path_start..].find(' ') {
                        let lib_path = &output_str[path_start..path_start + path_end];
                        if let Ok(readlink_output) = Command::new("readlink").arg(lib_path).output()
                        {
                            if let Ok(link_str) = String::from_utf8(readlink_output.stdout) {
                                if let Some(version_match) = link_str.split('-').next_back() {
                                    return Some(version_match.trim().to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    #[cfg(not(target_os = "linux"))]
    fn detect_glibc() -> Option<String> {
        None
    }

    pub fn fingerprint(&self) -> String {
        let mut parts = vec![self.os.clone()];

        if let Some(distro) = &self.distro {
            if let Some(version) = &self.version {
                parts.push(format!("{distro}{version}"));
            } else {
                parts.push(distro.clone());
            }
        }

        parts.push(self.arch.clone());

        if let Some(glibc) = &self.glibc {
            parts.push(format!("glibc{glibc}"));
        }

        parts.join("-")
    }

    pub fn to_tag_suffix(&self) -> String {
        // Map architecture to match binary naming
        let arch = match self.arch.as_str() {
            "x64" => "amd64",
            "arm64" => "arm64",
            "arm32" => "arm32",
            other => other,
        };

        match self.os.as_str() {
            "linux" => {
                // For Linux, use distro-specific naming to match binary names
                match (&self.distro, &self.version) {
                    (Some(distro), Some(version)) => {
                        match distro.as_str() {
                            "ubuntu" => format!("ubuntu-{}-{}", version, arch),
                            "debian" => {
                                // Map Debian version numbers to codenames
                                let codename = match version.as_str() {
                                    "12" => "bookworm",
                                    "11" => "bullseye",
                                    "10" => "buster",
                                    "9" => "stretch",
                                    _ => version, // fallback to version number
                                };
                                format!("debian-{}-{}", codename, arch)
                            }
                            "alpine" => format!("alpine-{}", arch),
                            "arch" => format!("arch-{}", arch),
                            _ => format!("{}-{}-{}", distro, version, arch),
                        }
                    }
                    (Some(distro), None) => match distro.as_str() {
                        "alpine" => format!("alpine-{}", arch),
                        "arch" => format!("arch-{}", arch),
                        _ => format!("{}-{}", distro, arch),
                    },
                    _ => {
                        // Fallback to generic Linux naming
                        format!("linux-{}", arch)
                    }
                }
            }
            "macos" => {
                // For macOS, use version-specific naming to match binary names
                if let Some(version) = &self.version {
                    // Map major version to full macOS version for compatibility
                    let macos_version = match version.as_str() {
                        "15" => "15",
                        "14" => "14",
                        "13" => "13",
                        "12" => "12",
                        _ => version,
                    };
                    format!("macos-{}-{}", macos_version, arch)
                } else {
                    format!("macos-{}", arch)
                }
            }
            "windows" => {
                // For Windows, use server version naming
                format!("windows-2022-{}", arch)
            }
            _ => {
                // Fallback for unknown OS
                format!("{}-{}", self.os, arch)
            }
        }
    }

    pub fn is_valid_tag_suffix(suffix: &str) -> bool {
        let parts: Vec<&str> = suffix.split('-').collect();

        // Must have at least 2 parts (os-arch or distro-arch)
        if parts.len() < 2 {
            return false;
        }

        // Last part should be a valid architecture
        let arch = parts.last().unwrap();
        let valid_arch = ["amd64", "arm64", "arm32", "x86"];
        if !valid_arch.contains(arch) {
            return false;
        }

        // Check common platform patterns
        match parts.len() {
            2 => {
                // Simple os-arch format (alpine-amd64, arch-amd64, linux-amd64, darwin-arm64)
                let os = parts[0];
                let valid_simple_os = ["alpine", "arch", "darwin", "linux", "macos", "windows"];
                valid_simple_os.contains(&os)
            }
            3 => {
                // distro-version-arch or os-version-arch format
                let os_or_distro = parts[0];
                let valid_distros = ["ubuntu", "debian", "macos", "windows"];
                valid_distros.contains(&os_or_distro)
            }
            4 => {
                // debian-codename-arch or windows-server-version-arch
                let distro = parts[0];
                match distro {
                    "debian" => {
                        let codename = parts[1];
                        let valid_codenames = ["bookworm", "bullseye", "buster", "stretch"];
                        valid_codenames.contains(&codename)
                    }
                    "windows" => parts[1] == "2022" || parts[1] == "2019",
                    _ => false,
                }
            }
            _ => false,
        }
    }

    pub fn system_resources(&self) -> &'static SystemResources {
        SystemResources::detect()
    }

    pub fn get_build_env(&self) -> std::collections::HashMap<String, String> {
        let resources = self.system_resources();
        let mut env = std::collections::HashMap::new();

        env.insert("CPU_COUNT".to_string(), resources.cpu_cores.to_string());

        let is_ci = std::env::var("CI").is_ok() || std::env::var("GITHUB_ACTIONS").is_ok();
        let mem_per_job = if is_ci { 1.5 } else { 2.0 };
        let mem_jobs = (resources.available_memory_gb / mem_per_job) as usize;
        let cpu_jobs = if is_ci {
            resources.cpu_cores
        } else {
            resources.cpu_cores.min(8)
        };
        let jobs = std::cmp::max(1, std::cmp::min(cpu_jobs, mem_jobs));

        env.insert("MAKE_OPTS".to_string(), format!("-j{jobs}"));
        env.insert("MAKEFLAGS".to_string(), format!("-j{jobs}"));
        env.insert("BUNDLE_JOBS".to_string(), jobs.to_string());
        env.insert("CMAKE_BUILD_PARALLEL_LEVEL".to_string(), jobs.to_string());

        env
    }
}

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
}

fn detect_available_memory_gb() -> f64 {
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("sysctl").args(["-n", "hw.memsize"]).output() {
            if let Ok(mem_str) = String::from_utf8(output.stdout) {
                if let Ok(mem_bytes) = mem_str.trim().parse::<u64>() {
                    return mem_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            let mut mem_available = None;
            let mut mem_total = None;

            for line in meminfo.lines() {
                if line.starts_with("MemAvailable:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = kb_str.parse::<u64>() {
                            mem_available = Some(kb as f64 / (1024.0 * 1024.0));
                        }
                    }
                } else if line.starts_with("MemTotal:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = kb_str.parse::<u64>() {
                            mem_total = Some(kb as f64 / (1024.0 * 1024.0));
                        }
                    }
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
        {
            if let Ok(uptime_str) = String::from_utf8(output.stdout) {
                let load_part = uptime_str
                    .split("load averages:")
                    .nth(1)
                    .or_else(|| uptime_str.split("load average:").nth(1));

                if let Some(load_part) = load_part {
                    if let Some(first_load) = load_part.split_whitespace().next() {
                        if let Ok(load) = first_load.trim().parse::<f32>() {
                            let cpu_cores = num_cpus::get() as f32;
                            let cpu_load = (load / cpu_cores) * 100.0;
                            return cpu_load.min(100.0);
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("wmic")
            .args(["cpu", "get", "loadpercentage", "/value"])
            .output()
        {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                for line in output_str.lines() {
                    if let Some(value) = line.strip_prefix("LoadPercentage=") {
                        if let Ok(load) = value.trim().parse::<f32>() {
                            return load;
                        }
                    }
                }
            }
        }

        if let Ok(output) = Command::new("powershell")
            .args(["-Command", "Get-WmiObject -Class Win32_Processor | Measure-Object -Property LoadPercentage -Average | Select-Object -ExpandProperty Average"])
            .output()
        {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                if let Ok(load) = output_str.trim().parse::<f32>() {
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
        {
            if let Ok(json_str) = String::from_utf8(output.stdout) {
                if json_str.contains("SSD") || json_str.contains("Flash") {
                    if json_str.contains("NVMe") || json_str.contains("PCIe") {
                        return (DiskType::NvmeSsd, 2000.0);
                    } else {
                        return (DiskType::SataSsd, 500.0);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
            for line in mounts.lines() {
                if line.contains(" / ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(device) = parts.first() {
                        let device_name = device.trim_start_matches("/dev/");

                        if device_name.starts_with("nvme") {
                            return (DiskType::NvmeSsd, 2000.0);
                        }

                        let sys_path = format!("/sys/block/{}/queue/rotational", device_name);
                        if let Ok(rotational) = std::fs::read_to_string(&sys_path) {
                            if rotational.trim() == "0" {
                                return (DiskType::SataSsd, 500.0);
                            }
                        }
                    }
                    break;
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
        {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                if output_str.contains("NVMe") || output_str.contains("PCIe") {
                    return (DiskType::NvmeSsd, 2000.0);
                } else if output_str.contains("SSD") {
                    return (DiskType::SataSsd, 500.0);
                }
            }
        }
    }

    (DiskType::SataSsd, 500.0)
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.fingerprint())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_detection() {
        let platform = Platform::detect().unwrap();

        assert!(!platform.os.is_empty());
        assert!(!platform.arch.is_empty());

        assert!(matches!(
            platform.os.as_str(),
            "linux" | "macos" | "windows"
        ));

        assert!(matches!(platform.arch.as_str(), "x64" | "arm64" | "arm32"));
    }

    #[test]
    fn test_fingerprint_generation() {
        let platform = Platform {
            os: "linux".to_string(),
            arch: "x64".to_string(),
            distro: Some("ubuntu".to_string()),
            version: Some("22.04".to_string()),
            glibc: Some("2.35".to_string()),
        };

        let fingerprint = platform.fingerprint();
        assert_eq!(fingerprint, "linux-ubuntu22.04-x64-glibc2.35");
    }

    #[test]
    fn test_tag_suffix_generation() {
        // Test Ubuntu
        let ubuntu_platform = Platform {
            os: "linux".to_string(),
            arch: "x64".to_string(),
            distro: Some("ubuntu".to_string()),
            version: Some("22.04".to_string()),
            glibc: Some("2.35".to_string()),
        };
        assert_eq!(ubuntu_platform.to_tag_suffix(), "ubuntu-22.04-amd64");

        // Test Debian
        let debian_platform = Platform {
            os: "linux".to_string(),
            arch: "arm64".to_string(),
            distro: Some("debian".to_string()),
            version: Some("12".to_string()),
            glibc: Some("2.36".to_string()),
        };
        assert_eq!(debian_platform.to_tag_suffix(), "debian-bookworm-arm64");

        // Test Alpine
        let alpine_platform = Platform {
            os: "linux".to_string(),
            arch: "x64".to_string(),
            distro: Some("alpine".to_string()),
            version: None,
            glibc: None,
        };
        assert_eq!(alpine_platform.to_tag_suffix(), "alpine-amd64");

        // Test Arch Linux
        let arch_platform = Platform {
            os: "linux".to_string(),
            arch: "x64".to_string(),
            distro: Some("arch".to_string()),
            version: None,
            glibc: None,
        };
        assert_eq!(arch_platform.to_tag_suffix(), "arch-amd64");

        // Test macOS
        let macos_platform = Platform {
            os: "macos".to_string(),
            arch: "arm64".to_string(),
            distro: Some("darwin".to_string()),
            version: Some("15".to_string()),
            glibc: None,
        };
        assert_eq!(macos_platform.to_tag_suffix(), "macos-15-arm64");

        // Test Windows
        let windows_platform = Platform {
            os: "windows".to_string(),
            arch: "x64".to_string(),
            distro: None,
            version: None,
            glibc: None,
        };
        assert_eq!(windows_platform.to_tag_suffix(), "windows-2022-amd64");
    }

    #[test]
    fn test_valid_tag_suffix() {
        // Test valid suffixes
        assert!(Platform::is_valid_tag_suffix("ubuntu-22.04-amd64"));
        assert!(Platform::is_valid_tag_suffix("debian-bookworm-arm64"));
        assert!(Platform::is_valid_tag_suffix("alpine-amd64"));
        assert!(Platform::is_valid_tag_suffix("arch-amd64"));
        assert!(Platform::is_valid_tag_suffix("darwin-arm64"));
        assert!(Platform::is_valid_tag_suffix("macos-15-arm64"));
        assert!(Platform::is_valid_tag_suffix("windows-2022-amd64"));

        // Test invalid suffixes
        assert!(!Platform::is_valid_tag_suffix("invalid"));
        assert!(!Platform::is_valid_tag_suffix("ubuntu-amd64-extra-part"));
        assert!(!Platform::is_valid_tag_suffix("unknown-distro-amd64"));
        assert!(!Platform::is_valid_tag_suffix("ubuntu-22.04-invalid-arch"));
    }

    #[test]
    fn test_build_env_generation() {
        let platform = Platform::detect().unwrap();
        let env = platform.get_build_env();

        assert!(env.contains_key("CPU_COUNT"));
        assert!(env.contains_key("MAKE_OPTS"));
        assert!(env.contains_key("MAKEFLAGS"));
        assert!(env.contains_key("BUNDLE_JOBS"));
        assert!(env.contains_key("CMAKE_BUILD_PARALLEL_LEVEL"));

        if let Some(make_opts) = env.get("MAKE_OPTS") {
            assert!(make_opts.starts_with("-j"));
            let jobs_str = &make_opts[2..];
            let jobs: usize = jobs_str.parse().expect("Should be valid number");
            assert!(jobs > 0);
        }
    }

    #[test]
    fn test_system_resources_detection() {
        let resources = SystemResources::detect();

        assert!(resources.cpu_cores > 0);
        assert!(resources.available_memory_gb > 0.0);
        assert!(resources.max_parallel_chunks > 0);
        assert!(resources.disk_speed_estimate_mb_s > 0.0);
    }

    #[test]
    fn test_system_resources() {
        let platform = Platform::detect().unwrap();
        let resources = platform.system_resources();
        assert!(resources.cpu_cores > 0);
    }
}
