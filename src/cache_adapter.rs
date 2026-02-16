use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheAdapterKind {
    Archive,
    Cas,
    CasOci,
    CasBazel,
}

impl CacheAdapterKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            CacheAdapterKind::Archive => "archive",
            CacheAdapterKind::Cas => "cas",
            CacheAdapterKind::CasOci => "cas-oci",
            CacheAdapterKind::CasBazel => "cas-bazel",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterDetection {
    pub kind: CacheAdapterKind,
    pub reason: &'static str,
}

pub fn detect_layout(path: &Path) -> AdapterDetection {
    if !path.is_dir() {
        return AdapterDetection {
            kind: CacheAdapterKind::Archive,
            reason: "target is not a directory",
        };
    }

    if looks_like_oci_layout(path) {
        return AdapterDetection {
            kind: CacheAdapterKind::CasOci,
            reason: "detected OCI index + blobs/sha256 layout",
        };
    }

    if looks_like_bazel_disk_cache(path) {
        return AdapterDetection {
            kind: CacheAdapterKind::CasBazel,
            reason: "detected Bazel ac/cas directory layout",
        };
    }

    AdapterDetection {
        kind: CacheAdapterKind::Archive,
        reason: "no known content-addressed layout markers found",
    }
}

pub fn detect_restore_transport(
    storage_mode: Option<&str>,
    cas_layout: Option<&str>,
) -> CacheAdapterKind {
    match storage_mode {
        Some("archive") => CacheAdapterKind::Archive,
        Some("cas") => detect_cas_layout(cas_layout).unwrap_or(CacheAdapterKind::Cas),
        _ => CacheAdapterKind::Archive,
    }
}

fn detect_cas_layout(cas_layout: Option<&str>) -> Option<CacheAdapterKind> {
    match cas_layout {
        Some("oci-v1") => Some(CacheAdapterKind::CasOci),
        Some("bazel-v2") => Some(CacheAdapterKind::CasBazel),
        Some("file-v1") => Some(CacheAdapterKind::Cas),
        _ => None,
    }
}

fn looks_like_oci_layout(path: &Path) -> bool {
    path.join("index.json").is_file()
        && path.join("oci-layout").is_file()
        && path.join("blobs").join("sha256").is_dir()
}

fn looks_like_bazel_disk_cache(path: &Path) -> bool {
    path.join("ac").is_dir() && path.join("cas").is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn detect_layout_returns_archive_for_file_target() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("file.txt");
        fs::write(&file_path, "abc").unwrap();

        let detection = detect_layout(&file_path);
        assert_eq!(detection.kind, CacheAdapterKind::Archive);
    }

    #[test]
    fn detect_layout_detects_oci_layout() {
        let temp_dir = TempDir::new().unwrap();
        fs::create_dir_all(temp_dir.path().join("blobs").join("sha256")).unwrap();
        fs::write(temp_dir.path().join("index.json"), "{}").unwrap();
        fs::write(temp_dir.path().join("oci-layout"), "{}").unwrap();

        let detection = detect_layout(temp_dir.path());
        assert_eq!(detection.kind, CacheAdapterKind::CasOci);
    }

    #[test]
    fn detect_layout_detects_bazel_layout() {
        let temp_dir = TempDir::new().unwrap();
        fs::create_dir_all(temp_dir.path().join("ac")).unwrap();
        fs::create_dir_all(temp_dir.path().join("cas")).unwrap();

        let detection = detect_layout(temp_dir.path());
        assert_eq!(detection.kind, CacheAdapterKind::CasBazel);
    }

    #[test]
    fn detect_restore_transport_uses_archive_for_unknown_algorithm() {
        assert_eq!(
            detect_restore_transport(None, None),
            CacheAdapterKind::Archive
        );
        assert_eq!(
            detect_restore_transport(None, None),
            CacheAdapterKind::Archive
        );
    }

    #[test]
    fn detect_restore_transport_uses_storage_mode_and_layout() {
        assert_eq!(
            detect_restore_transport(Some("cas"), Some("oci-v1")),
            CacheAdapterKind::CasOci
        );
        assert_eq!(
            detect_restore_transport(Some("cas"), Some("bazel-v2")),
            CacheAdapterKind::CasBazel
        );
        assert_eq!(
            detect_restore_transport(Some("cas"), Some("file-v1")),
            CacheAdapterKind::Cas
        );
    }

    #[test]
    fn detect_restore_transport_uses_generic_cas_for_unknown_layout() {
        assert_eq!(
            detect_restore_transport(Some("cas"), Some("unknown")),
            CacheAdapterKind::Cas
        );
    }

    #[test]
    fn detect_restore_transport_ignores_unknown_storage_mode() {
        assert_eq!(
            detect_restore_transport(Some("future"), Some("oci-v1")),
            CacheAdapterKind::Archive
        );
    }

    #[test]
    fn detect_restore_transport_prefers_explicit_archive_mode() {
        assert_eq!(
            detect_restore_transport(Some("archive"), Some("oci-v1")),
            CacheAdapterKind::Archive
        );
    }
}
