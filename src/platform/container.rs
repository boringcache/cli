/// Container detection utilities
///
/// Provides reliable detection of container environments including
/// Docker, Podman, and Kubernetes for accurate platform identification.
pub struct ContainerDetection;

impl ContainerDetection {
    /// Detect if we're running in a container environment
    pub fn is_container() -> bool {
        #[cfg(target_os = "linux")]
        {
            Self::check_container_files() || Self::check_container_env() || Self::check_cgroup()
        }

        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    #[cfg(target_os = "linux")]
    fn check_container_files() -> bool {
        std::path::Path::new("/.dockerenv").exists() || // Docker
        std::path::Path::new("/run/.containerenv").exists() // Podman
    }

    #[cfg(target_os = "linux")]
    fn check_container_env() -> bool {
        std::env::var("KUBERNETES_SERVICE_HOST").is_ok() || // Kubernetes
        std::env::var("container").is_ok() // Generic container env
    }

    #[cfg(target_os = "linux")]
    fn check_cgroup() -> bool {
        if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
            return cgroup.contains("/docker/")
                || cgroup.contains("/kubepods/")
                || cgroup.contains("/lxc/")
                || cgroup.contains("/containerd/");
        }
        false
    }

    /// Get container type if running in a container
    pub fn container_type() -> Option<&'static str> {
        #[cfg(target_os = "linux")]
        {
            if std::path::Path::new("/.dockerenv").exists() {
                return Some("docker");
            }
            if std::path::Path::new("/run/.containerenv").exists() {
                return Some("podman");
            }
            if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
                return Some("kubernetes");
            }
            if std::env::var("container").is_ok() {
                return Some("generic");
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_detection() {
        // This test will pass on both container and non-container environments
        let is_container = ContainerDetection::is_container();
        let container_type = ContainerDetection::container_type();

        if is_container {
            assert!(container_type.is_some());
        }
    }
}
