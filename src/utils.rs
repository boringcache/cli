/// Utility functions and common patterns for BoringCache CLI
///
/// This module provides reusable utilities, result handling patterns,
/// and common operations to reduce code duplication across the codebase.
use crate::types::Result;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Result extension for common error handling patterns
pub trait ResultExt<T> {
    /// Add context with a file path for better error messages
    fn with_path_context<P: AsRef<Path>>(self, path: P, operation: &str) -> Result<T>;

    /// Add context with a workspace for better error messages
    fn with_workspace_context(self, workspace: &str, operation: &str) -> Result<T>;

    /// Convert to a more specific error type with timing information
    fn with_timing(self, start: Instant, operation: &str) -> Result<T>;
}

impl<T, E> ResultExt<T> for std::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn with_path_context<P: AsRef<Path>>(self, path: P, operation: &str) -> Result<T> {
        self.map_err(|e| {
            anyhow::anyhow!(
                "Failed to {} '{}': {}",
                operation,
                path.as_ref().display(),
                e
            )
        })
    }

    fn with_workspace_context(self, workspace: &str, operation: &str) -> Result<T> {
        self.map_err(|e| {
            anyhow::anyhow!("Failed to {} workspace '{}': {}", operation, workspace, e)
        })
    }

    fn with_timing(self, start: Instant, operation: &str) -> Result<T> {
        self.map_err(|e| {
            let duration = start.elapsed();
            anyhow::anyhow!("{} failed after {:?}: {}", operation, duration, e)
        })
    }
}

/// Path utilities for consistent path handling
pub struct PathUtils;

impl PathUtils {
    /// Expand tilde path to full path
    pub fn expand_tilde<P: AsRef<Path>>(path: P) -> PathBuf {
        let path = path.as_ref();
        if let Some(path_str) = path.to_str() {
            if let Some(stripped) = path_str.strip_prefix('~') {
                if let Some(home) = dirs::home_dir() {
                    return home.join(stripped.strip_prefix('/').unwrap_or(stripped));
                }
            }
        }
        path.to_path_buf()
    }

    /// Check if a path is writable by attempting to create a test file
    pub fn is_writable<P: AsRef<Path>>(path: P) -> Result<bool> {
        use std::fs::OpenOptions;
        use uuid::Uuid;

        let path = path.as_ref();
        let test_file_name = format!(".boringcache_test_{}", Uuid::new_v4());
        let test_file = path.join(test_file_name);

        match OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&test_file)
        {
            Ok(mut file) => {
                use std::io::Write;
                let write_result = file.write_all(b"test");
                let _ = std::fs::remove_file(&test_file);
                Ok(write_result.is_ok())
            }
            Err(_) => Ok(false),
        }
    }

    /// Get the parent directory of a path, creating it if necessary
    pub fn ensure_parent_dir<P: AsRef<Path>>(path: P) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .with_path_context(parent, "create parent directory")?;
            }
        }
        Ok(())
    }
}

/// Timing utilities for performance measurement
pub struct TimingUtils;

impl TimingUtils {
    /// Measure the duration of a function execution
    pub fn measure<F, R>(_operation: &str, f: F) -> (R, Duration)
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = f();
        let duration = start.elapsed();
        (result, duration)
    }

    /// Measure the duration of an async function execution
    pub async fn measure_async<F, Fut, R>(_operation: &str, f: F) -> (R, Duration)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = R>,
    {
        let start = Instant::now();
        let result = f().await;
        let duration = start.elapsed();
        (result, duration)
    }

    /// Format duration in a human-readable way
    pub fn format_duration(duration: Duration) -> String {
        let total_ms = duration.as_millis();
        if total_ms < 1000 {
            format!("{}ms", total_ms)
        } else if total_ms < 60_000 {
            format!("{:.1}s", total_ms as f64 / 1000.0)
        } else {
            let total_secs = duration.as_secs();
            let minutes = total_secs / 60;
            let seconds = total_secs % 60;
            format!("{}m{}s", minutes, seconds)
        }
    }
}

/// String utilities for common string operations
pub struct StringUtils;

impl StringUtils {
    /// Truncate a string to a maximum length with ellipsis
    pub fn truncate(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            format!("{}...", &s[..max_len.saturating_sub(3)])
        }
    }

    /// Pluralize a word based on count
    pub fn pluralize(word: &str, count: usize) -> String {
        if count == 1 {
            word.to_string()
        } else {
            format!("{}s", word)
        }
    }

    /// Format file count with proper pluralization
    pub fn format_file_count(count: u32) -> String {
        format!("{} {}", count, Self::pluralize("file", count as usize))
    }
}

/// Validation utilities for common input validation
pub struct ValidationUtils;

impl ValidationUtils {
    /// Validate that a tag is non-empty and doesn't contain invalid characters
    pub fn validate_tag(tag: &str) -> Result<()> {
        if tag.is_empty() {
            anyhow::bail!("Tag cannot be empty");
        }

        if tag.contains('\0') || tag.contains('\n') || tag.contains('\r') {
            anyhow::bail!("Tag cannot contain null bytes or newlines");
        }

        if tag.len() > 256 {
            anyhow::bail!("Tag cannot be longer than 256 characters");
        }

        Ok(())
    }

    /// Validate a file path exists and is accessible
    pub fn validate_path_exists<P: AsRef<Path>>(path: P) -> Result<()> {
        let path = path.as_ref();
        if !path.exists() {
            anyhow::bail!("Path does not exist: {}", path.display());
        }

        // Try to read metadata to ensure we can access the path
        std::fs::metadata(path).with_path_context(path, "access")?;

        Ok(())
    }

    /// Validate a workspace slug format
    pub fn validate_workspace_slug(slug: &str) -> Result<()> {
        if slug.is_empty() {
            anyhow::bail!("Workspace slug cannot be empty");
        }

        let parts: Vec<&str> = slug.split('/').collect();
        if parts.len() != 2 {
            anyhow::bail!(
                "Invalid workspace format '{}'. Expected format: namespace/workspace",
                slug
            );
        }

        for (i, part) in parts.iter().enumerate() {
            let field_name = if i == 0 { "namespace" } else { "workspace" };
            if part.is_empty() {
                anyhow::bail!("{} cannot be empty in '{}'", field_name, slug);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_path_utils_expand_tilde() {
        let home_path = PathUtils::expand_tilde("~/test");
        // Should not start with tilde after expansion
        assert!(!home_path.to_string_lossy().starts_with('~'));

        let regular_path = PathUtils::expand_tilde("/absolute/path");
        assert_eq!(regular_path, PathBuf::from("/absolute/path"));
    }

    #[test]
    fn test_timing_utils_format_duration() {
        assert_eq!(
            TimingUtils::format_duration(Duration::from_millis(500)),
            "500ms"
        );
        assert_eq!(
            TimingUtils::format_duration(Duration::from_millis(1500)),
            "1.5s"
        );
        assert_eq!(
            TimingUtils::format_duration(Duration::from_secs(90)),
            "1m30s"
        );
    }

    #[test]
    fn test_string_utils_truncate() {
        assert_eq!(StringUtils::truncate("short", 10), "short");
        assert_eq!(StringUtils::truncate("very long string", 10), "very lo...");
    }

    #[test]
    fn test_string_utils_pluralize() {
        assert_eq!(StringUtils::pluralize("file", 1), "file");
        assert_eq!(StringUtils::pluralize("file", 0), "files");
        assert_eq!(StringUtils::pluralize("file", 2), "files");
    }

    #[test]
    fn test_validation_utils_validate_tag() {
        assert!(ValidationUtils::validate_tag("valid-tag").is_ok());
        assert!(ValidationUtils::validate_tag("").is_err());
        assert!(ValidationUtils::validate_tag("tag\0").is_err());
        assert!(ValidationUtils::validate_tag("tag\n").is_err());
    }

    #[test]
    fn test_validation_utils_validate_workspace_slug() {
        assert!(ValidationUtils::validate_workspace_slug("namespace/workspace").is_ok());
        assert!(ValidationUtils::validate_workspace_slug("invalid").is_err());
        assert!(ValidationUtils::validate_workspace_slug("too/many/parts").is_err());
        assert!(ValidationUtils::validate_workspace_slug("").is_err());
    }
}
