/// Centralized domain types and result definitions for BoringCache CLI
///
/// This module consolidates common types, result patterns, and domain models
/// to improve maintainability and reduce duplication across the codebase.
use anyhow::Result as AnyhowResult;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Standard Result type used throughout the application
pub type Result<T> = AnyhowResult<T>;

/// Cache operation result with metrics
#[derive(Debug)]
pub struct OperationResult<T> {
    pub result: T,
    pub duration: Duration,
    pub bytes_processed: Option<u64>,
}

impl<T> OperationResult<T> {
    pub fn new(result: T, duration: Duration) -> Self {
        Self {
            result,
            duration,
            bytes_processed: None,
        }
    }

    pub fn with_bytes(result: T, duration: Duration, bytes: u64) -> Self {
        Self {
            result,
            duration,
            bytes_processed: Some(bytes),
        }
    }
}

/// Workspace identifier with validation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkspaceId {
    pub namespace: String,
    pub name: String,
}

impl WorkspaceId {
    pub fn new(namespace: String, name: String) -> Result<Self> {
        Self::validate_name(&namespace, "namespace")?;
        Self::validate_name(&name, "workspace")?;
        Ok(Self { namespace, name })
    }

    pub fn from_slug(slug: &str) -> Result<Self> {
        let parts: Vec<&str> = slug.split('/').collect();
        if parts.len() != 2 {
            anyhow::bail!(
                "Invalid workspace format '{}'. Expected format: namespace/workspace",
                slug
            );
        }
        Self::new(parts[0].to_string(), parts[1].to_string())
    }

    pub fn slug(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }

    fn validate_name(name: &str, field: &str) -> Result<()> {
        if name.is_empty() {
            anyhow::bail!("{} cannot be empty", field);
        }

        let is_valid = name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
            && !name.starts_with('-')
            && !name.ends_with('-')
            && !name.starts_with('.')
            && !name.ends_with('.');

        if !is_valid {
            anyhow::bail!("Invalid {} '{}'. Must contain only alphanumeric characters, hyphens, underscores, and dots. Cannot start or end with hyphens or dots.", field, name);
        }

        Ok(())
    }
}

/// Cache entry identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub workspace: WorkspaceId,
    pub tag: String,
    pub path: Option<PathBuf>,
}

impl CacheKey {
    pub fn new(workspace: WorkspaceId, tag: String, path: Option<PathBuf>) -> Self {
        Self {
            workspace,
            tag,
            path,
        }
    }
}

impl std::fmt::Display for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.path {
            Some(path) => write!(f, "{}:{}", self.tag, path.display()),
            None => write!(f, "{}", self.tag),
        }
    }
}

/// Size information with human-readable formatting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteSize(pub u64);

impl ByteSize {
    pub fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    pub fn bytes(&self) -> u64 {
        self.0
    }

    pub fn as_mb(&self) -> f64 {
        self.0 as f64 / (1024.0 * 1024.0)
    }

    pub fn as_gb(&self) -> f64 {
        self.0 as f64 / (1024.0 * 1024.0 * 1024.0)
    }
}

impl std::fmt::Display for ByteSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.0;
        if bytes < 1024 {
            write!(f, "{} B", bytes)
        } else if bytes < 1024 * 1024 {
            write!(f, "{:.1} KB", bytes as f64 / 1024.0)
        } else if bytes < 1024 * 1024 * 1024 {
            write!(f, "{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
        } else {
            write!(f, "{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        }
    }
}

/// Archive metadata
#[derive(Debug, Clone)]
pub struct ArchiveMetadata {
    pub compressed_size: ByteSize,
    pub uncompressed_size: ByteSize,
    pub file_count: u32,
    pub content_hash: String,
    pub compression_algorithm: String,
}

impl ArchiveMetadata {
    pub fn compression_ratio(&self) -> f64 {
        if self.uncompressed_size.bytes() == 0 {
            0.0
        } else {
            self.compressed_size.bytes() as f64 / self.uncompressed_size.bytes() as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workspace_id_validation() {
        assert!(WorkspaceId::new("valid".to_string(), "name".to_string()).is_ok());
        assert!(WorkspaceId::new("valid-name".to_string(), "another_name".to_string()).is_ok());
        assert!(WorkspaceId::new("valid.name".to_string(), "name123".to_string()).is_ok());

        assert!(WorkspaceId::new("-invalid".to_string(), "name".to_string()).is_err());
        assert!(WorkspaceId::new("invalid-".to_string(), "name".to_string()).is_err());
        assert!(WorkspaceId::new(".invalid".to_string(), "name".to_string()).is_err());
        assert!(WorkspaceId::new("invalid.".to_string(), "name".to_string()).is_err());
        assert!(WorkspaceId::new("".to_string(), "name".to_string()).is_err());
    }

    #[test]
    fn test_workspace_id_from_slug() {
        let ws = WorkspaceId::from_slug("namespace/workspace").unwrap();
        assert_eq!(ws.namespace, "namespace");
        assert_eq!(ws.name, "workspace");
        assert_eq!(ws.slug(), "namespace/workspace");

        assert!(WorkspaceId::from_slug("invalid").is_err());
        assert!(WorkspaceId::from_slug("too/many/parts").is_err());
    }

    #[test]
    fn test_byte_size_formatting() {
        assert_eq!(ByteSize::new(512).to_string(), "512 B");
        assert_eq!(ByteSize::new(1536).to_string(), "1.5 KB");
        assert_eq!(ByteSize::new(1572864).to_string(), "1.5 MB");
        assert_eq!(ByteSize::new(1610612736).to_string(), "1.5 GB");
    }
}
