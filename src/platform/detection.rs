use crate::platform::container::ContainerDetection;
use crate::types::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Platform {
    pub os: String,
    pub arch: String,
    pub distro: Option<String>,
    pub version: Option<String>,

    #[serde(skip)]
    tag_suffix_cache: std::sync::OnceLock<String>,
}

#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub platform: Platform,
    pub is_container: bool,
    pub tag_suffix: String,
}

impl Platform {
    pub fn detect() -> Result<Self> {
        let os = Self::detect_os();
        let arch = Self::detect_arch();
        let (distro, version) = Self::detect_distro_and_version();

        Ok(Platform {
            os,
            arch,
            distro,
            version,
            tag_suffix_cache: std::sync::OnceLock::new(),
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_testing(
        os: &str,
        arch: &str,
        distro: Option<&str>,
        version: Option<&str>,
    ) -> Self {
        Platform {
            os: os.to_string(),
            arch: arch.to_string(),
            distro: distro.map(|s| s.to_string()),
            version: version.map(|s| s.to_string()),
            tag_suffix_cache: std::sync::OnceLock::new(),
        }
    }

    pub fn to_info(&self) -> PlatformInfo {
        let is_container = ContainerDetection::is_container();
        let tag_suffix = self.to_tag_suffix();

        PlatformInfo {
            platform: self.clone(),
            is_container,
            tag_suffix,
        }
    }

    #[inline]
    pub fn append_to_tag(&self, tag: &str) -> String {
        if Self::has_platform_suffix(tag) {
            tag.to_string()
        } else {
            format!("{}-{}", tag, self.to_tag_suffix())
        }
    }

    #[inline]
    pub fn has_platform_suffix(tag: &str) -> bool {
        if let Some(last_part) = tag.rsplit('-').next() {
            if matches!(last_part, "x86_64" | "arm64" | "arm32" | "x86") {
                return true;
            }
        }

        let tag_bytes = tag.as_bytes();
        const PATTERNS: &[&[u8]] = &[
            b"-ubuntu-",
            b"-debian-",
            b"-alpine-",
            b"-arch-",
            b"-macos-",
            b"-windows-",
            b"-linux-",
        ];

        for pattern in PATTERNS {
            if tag_bytes
                .windows(pattern.len())
                .any(|window| window == *pattern)
            {
                return true;
            }
        }

        false
    }

    #[inline]
    pub fn to_tag_suffix(&self) -> String {
        self.tag_suffix_cache
            .get_or_init(|| self.compute_tag_suffix())
            .clone()
    }

    fn compute_tag_suffix(&self) -> String {
        let arch = &self.arch;

        match self.os.as_str() {
            "linux" => match (&self.distro, &self.version) {
                (Some(distro), Some(version)) => {
                    format!("{}-{}-{}", distro, version, arch)
                }
                (Some(distro), None) => {
                    let default_version = match distro.as_str() {
                        "alpine" => "3",
                        "arch" => "rolling",
                        _ => "unknown",
                    };
                    format!("{}-{}-{}", distro, default_version, arch)
                }
                _ => format!("linux-unknown-{}", arch),
            },
            "macos" => {
                if let Some(version) = &self.version {
                    format!("macos-{}-{}", version, arch)
                } else {
                    format!("macos-unknown-{}", arch)
                }
            }
            "windows" => {
                if let Some(version) = &self.version {
                    format!("windows-{}-{}", version, arch)
                } else {
                    format!("windows-11-{}", arch)
                }
            }
            _ => format!("{}-unknown-{}", self.os, arch),
        }
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
            "x86_64" => "x86_64".to_string(),
            "aarch64" => "arm64".to_string(),
            "arm" => "arm32".to_string(),
            "x86" => "x86".to_string(),
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
        for path in ["/etc/os-release", "/usr/lib/os-release"] {
            if let Ok(contents) = std::fs::read_to_string(path) {
                let mut distro_id = None;
                let mut version_id = None;

                for line in contents.lines() {
                    if let Some((key, value)) = line.split_once('=') {
                        let value = value.trim_matches('"').trim_matches('\'');
                        match key {
                            "ID" => distro_id = Some(value.to_lowercase()),
                            "VERSION_ID" => version_id = Some(value.to_string()),
                            _ => {}
                        }
                    }
                }

                if let Some(id) = distro_id {
                    return Self::normalize_distro(&id, version_id.as_deref());
                }
            }
        }

        Self::detect_linux_fallback()
    }

    #[cfg(target_os = "linux")]
    fn normalize_distro(id: &str, version_id: Option<&str>) -> (Option<String>, Option<String>) {
        match id {
            "arch" => (Some("arch".to_string()), Some("rolling".to_string())),
            "alpine" => {
                let major = version_id.and_then(|v| v.split('.').next()).unwrap_or("3");
                (Some("alpine".to_string()), Some(major.to_string()))
            }
            "ubuntu" => {
                let major = version_id.and_then(|v| v.split('.').next()).unwrap_or("22");
                (Some("ubuntu".to_string()), Some(major.to_string()))
            }
            "debian" => {
                let major = version_id.and_then(|v| v.split('.').next()).unwrap_or("11");
                (Some("debian".to_string()), Some(major.to_string()))
            }
            "pop" | "elementary" | "linuxmint" | "zorin" => {
                let major = version_id.and_then(|v| v.split('.').next()).unwrap_or("22");
                (Some("ubuntu".to_string()), Some(major.to_string()))
            }
            "raspbian" | "kali" | "parrot" => {
                let major = version_id.and_then(|v| v.split('.').next()).unwrap_or("11");
                (Some("debian".to_string()), Some(major.to_string()))
            }
            "rhel" | "centos" | "fedora" | "opensuse" | "sles" => {
                let major = version_id.and_then(|v| v.split('.').next()).unwrap_or("0");
                (Some(id.to_string()), Some(major.to_string()))
            }
            _ => {
                if ContainerDetection::is_container() {
                    (Some("ubuntu".to_string()), Some("22".to_string()))
                } else {
                    let major = version_id.and_then(|v| v.split('.').next()).unwrap_or("0");
                    (Some(id.to_string()), Some(major.to_string()))
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn detect_linux_fallback() -> (Option<String>, Option<String>) {
        if std::path::Path::new("/etc/alpine-release").exists() {
            if let Ok(version) = std::fs::read_to_string("/etc/alpine-release") {
                let major = version.trim().split('.').next().unwrap_or("3");
                return (Some("alpine".to_string()), Some(major.to_string()));
            }
            return (Some("alpine".to_string()), Some("3".to_string()));
        }

        if std::path::Path::new("/etc/arch-release").exists() {
            return (Some("arch".to_string()), Some("rolling".to_string()));
        }

        if std::path::Path::new("/etc/debian_version").exists() {
            if let Ok(version) = std::fs::read_to_string("/etc/debian_version") {
                let major = version.trim().split('.').next().unwrap_or("11");
                return (Some("debian".to_string()), Some(major.to_string()));
            }
            return (Some("debian".to_string()), Some("11".to_string()));
        }

        if ContainerDetection::is_container() {
            (Some("ubuntu".to_string()), Some("22".to_string()))
        } else {
            (Some("linux".to_string()), Some("unknown".to_string()))
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn detect_linux_distro() -> (Option<String>, Option<String>) {
        (None, None)
    }

    #[cfg(target_os = "macos")]
    fn detect_macos_version() -> (Option<String>, Option<String>) {
        if let Ok(output) = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
        {
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

    pub fn is_valid_tag_suffix(suffix: &str) -> bool {
        let parts: Vec<&str> = suffix.split('-').collect();

        if parts.len() < 2 {
            return false;
        }

        let Some(arch) = parts.last() else {
            return false;
        };
        let valid_arch = ["x86_64", "arm64", "arm32", "x86"];
        if !valid_arch.contains(arch) {
            return false;
        }

        match parts.len() {
            2 => {
                let os = parts[0];
                let valid_simple_os = ["darwin", "linux"];
                valid_simple_os.contains(&os)
            }
            3 => {
                let os_or_distro = parts[0];
                let valid_distros = ["ubuntu", "debian", "alpine", "arch", "macos", "windows"];
                valid_distros.contains(&os_or_distro)
            }
            _ => false,
        }
    }

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
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_tag_suffix())
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
    }

    #[test]
    fn test_tag_suffix_generation() {
        let platform = Platform {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            distro: Some("ubuntu".to_string()),
            version: Some("22".to_string()),
            tag_suffix_cache: std::sync::OnceLock::new(),
        };
        assert_eq!(platform.to_tag_suffix(), "ubuntu-22-x86_64");
    }

    #[test]
    fn test_platform_tag_appending() {
        let platform = Platform {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            distro: Some("ubuntu".to_string()),
            version: Some("22".to_string()),
            tag_suffix_cache: std::sync::OnceLock::new(),
        };

        assert_eq!(
            platform.append_to_tag("ruby-3.3.4"),
            "ruby-3.3.4-ubuntu-22-x86_64"
        );

        assert_eq!(
            platform.append_to_tag("ruby-3.3.4-ubuntu-22-x86_64"),
            "ruby-3.3.4-ubuntu-22-x86_64"
        );
    }
}
