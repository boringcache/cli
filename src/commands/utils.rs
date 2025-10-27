use crate::config::Config;
use crate::progress::{format_bytes, Reporter};
use crate::ui;
use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;

pub fn expand_tilde_path(path: &str) -> String {
    if path.starts_with('~') {
        if let Some(home) = dirs::home_dir() {
            return path.replacen('~', &home.to_string_lossy(), 1);
        }
    }
    path.to_string()
}

pub fn get_workspace_name(workspace_option: Option<String>) -> Result<String> {
    if let Some(workspace) = workspace_option {
        return Ok(workspace);
    }

    if let Ok(workspace) = std::env::var("BORINGCACHE_DEFAULT_WORKSPACE") {
        if !workspace.trim().is_empty() {
            return Ok(workspace);
        }
    }

    match Config::load() {
        Ok(config) => {
            if let Some(default_workspace) = config.default_workspace {
                Ok(default_workspace)
            } else {
                Err(anyhow::anyhow!("No workspace specified. Set BORINGCACHE_DEFAULT_WORKSPACE env var or use 'boringcache config set default_workspace <name>'"))
            }
        }
        Err(_) => {
            Err(anyhow::anyhow!("No workspace specified and config not found. Set BORINGCACHE_DEFAULT_WORKSPACE env var or run 'boringcache auth' first"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveSpec {
    pub tag: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreSpec {
    pub tag: String,
    pub path: Option<String>,
}

#[derive(Debug, Error)]
pub enum IdentifierParseError {
    #[error("Invalid cache specifier '{input}'. Expected format 'tag:path' (example: 'ruby-deps:vendor/bundle').")]
    InvalidFormat { input: String },
    #[error("Tag is missing in '{input}'. Add a tag before ':'.")]
    MissingTag { input: String },
    #[error("Path is missing in '{input}'. Add a path after ':'.")]
    MissingPath { input: String },
}

pub fn parse_save_format(tag_path_string: &str) -> Result<SaveSpec, IdentifierParseError> {
    let trimmed = tag_path_string.trim();
    if trimmed.is_empty() {
        return Err(IdentifierParseError::InvalidFormat {
            input: tag_path_string.to_string(),
        });
    }

    let (tag_raw, path_raw) =
        trimmed
            .split_once(':')
            .ok_or_else(|| IdentifierParseError::InvalidFormat {
                input: tag_path_string.to_string(),
            })?;

    let tag = tag_raw.trim();
    if tag.is_empty() {
        return Err(IdentifierParseError::MissingTag {
            input: tag_path_string.to_string(),
        });
    }

    let path = path_raw.trim();
    if path.is_empty() {
        return Err(IdentifierParseError::MissingPath {
            input: tag_path_string.to_string(),
        });
    }

    Ok(SaveSpec {
        tag: tag.to_string(),
        path: path.to_string(),
    })
}

pub fn parse_restore_format(tag_path_string: &str) -> Result<RestoreSpec, IdentifierParseError> {
    let trimmed = tag_path_string.trim();
    if trimmed.is_empty() {
        return Err(IdentifierParseError::InvalidFormat {
            input: tag_path_string.to_string(),
        });
    }

    if let Some((tag_raw, path_raw)) = trimmed.split_once(':') {
        let tag = tag_raw.trim();
        if tag.is_empty() {
            return Err(IdentifierParseError::MissingTag {
                input: tag_path_string.to_string(),
            });
        }

        let path = path_raw.trim();
        let path = if path.is_empty() {
            None
        } else {
            Some(path.to_string())
        };

        Ok(RestoreSpec {
            tag: tag.to_string(),
            path,
        })
    } else {
        Ok(RestoreSpec {
            tag: trimmed.to_string(),
            path: None,
        })
    }
}

pub fn get_optimal_concurrency(operation_count: usize, operation_type: &str) -> usize {
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let base_concurrency = match operation_type {
        "save" => std::cmp::max(2, cpu_count / 2),
        "restore" => std::cmp::max(2, cpu_count),
        _ => 3,
    };

    let platform_adjusted = if cfg!(target_os = "macos") {
        if operation_type == "restore" {
            base_concurrency + 2
        } else {
            base_concurrency
        }
    } else if cfg!(target_os = "windows") {
        std::cmp::max(2, base_concurrency - 1)
    } else {
        base_concurrency
    };

    std::cmp::min(
        std::cmp::min(platform_adjusted, 8), // Never exceed 8 concurrent ops
        operation_count,                     // Don't spawn more tasks than operations
    )
}

pub fn display_concurrency_info(max_concurrent: usize, operation_type: &str) {
    ui::info(&format!(
        "Using {max_concurrent} concurrent {operation_type} operations"
    ));
}

/// Generic progress tracker for transfers (upload/download)
pub struct TransferProgress {
    reporter: Reporter,
    session_id: String,
    step: u8,
    total_bytes: u64,
    start: Instant,
    transferred_bytes: AtomicU64,
}

impl TransferProgress {
    pub fn new(reporter: Reporter, session_id: String, step: u8, total_bytes: u64) -> Self {
        Self {
            reporter,
            session_id,
            step,
            total_bytes,
            start: Instant::now(),
            transferred_bytes: AtomicU64::new(0),
        }
    }

    pub fn update(&self, bytes: u64) {
        let transferred = bytes.min(self.total_bytes);
        self.transferred_bytes.store(transferred, Ordering::Relaxed);
        self.emit_progress(transferred);
    }

    pub fn add(&self, bytes: u64) {
        let previous = self.transferred_bytes.fetch_add(bytes, Ordering::Relaxed);
        let transferred = (previous + bytes).min(self.total_bytes);
        self.emit_progress(transferred);
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn speed_mbps(&self) -> f64 {
        let bytes = self.transferred_bytes.load(Ordering::Relaxed);
        let elapsed = self.start.elapsed().as_secs_f64().max(0.001);
        calculate_speed_mbps(bytes, Duration::from_secs_f64(elapsed))
    }

    fn emit_progress(&self, transferred_bytes: u64) {
        let percent = calculate_percent(transferred_bytes, self.total_bytes);
        let speed_mbps = self.speed_mbps();

        let detail = format!(
            "[{}/{}] {:.0}% @ {:.1} MB/s",
            format_bytes(transferred_bytes),
            format_bytes(self.total_bytes),
            percent,
            speed_mbps
        );

        let _ =
            self.reporter
                .step_progress(self.session_id.clone(), self.step, percent, Some(detail));
    }
}

/// Calculate percentage with bounds checking
pub fn calculate_percent(current: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        ((current as f64 / total as f64) * 100.0).clamp(0.0, 100.0)
    }
}

/// Format duration in human-readable format
pub fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let millis = duration.subsec_millis();

    if total_secs == 0 {
        format!("{}ms", millis)
    } else if total_secs < 60 {
        format!("{}.{}s", total_secs, millis / 100)
    } else {
        let mins = total_secs / 60;
        let secs = total_secs % 60;
        format!("{}m {}s", mins, secs)
    }
}

/// Calculate transfer speed in MB/s using platform disk speed estimates
pub fn calculate_speed_mbps(bytes: u64, duration: Duration) -> f64 {
    let secs = duration.as_secs_f64().max(0.001);
    let calculated_speed = (bytes as f64 / (1024.0 * 1024.0)) / secs;

    // Use platform disk speed estimate as upper bound for realistic reporting
    let platform_resources = crate::platform::SystemResources::detect();
    let disk_speed_limit = platform_resources.disk_speed_estimate_mb_s;

    calculated_speed.min(disk_speed_limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_save_format_accepts_basic_pair() {
        let spec = parse_save_format("ruby-deps:vendor/bundle").unwrap();
        assert_eq!(spec.tag, "ruby-deps");
        assert_eq!(spec.path, "vendor/bundle");
    }

    #[test]
    fn parse_save_format_supports_windows_drive_paths() {
        let spec = parse_save_format("windows-app:C:\\Program Files\\App").unwrap();
        assert_eq!(spec.tag, "windows-app");
        assert_eq!(spec.path, "C:\\Program Files\\App");
    }

    #[test]
    fn parse_save_format_rejects_missing_path() {
        let err = parse_save_format("tag-only:").unwrap_err();
        assert!(
            matches!(err, IdentifierParseError::MissingPath { .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_restore_format_supports_tag_only() {
        let spec = parse_restore_format("ruby-deps").unwrap();
        assert_eq!(spec.tag, "ruby-deps");
        assert!(spec.path.is_none());
    }

    #[test]
    fn parse_restore_format_retains_complex_paths() {
        let spec = parse_restore_format("build-cache:complex:path:with:colons").unwrap();
        assert_eq!(spec.tag, "build-cache");
        assert_eq!(spec.path.as_deref(), Some("complex:path:with:colons"));
    }

    #[test]
    fn parse_restore_format_rejects_empty_input() {
        let err = parse_restore_format("").unwrap_err();
        assert!(
            matches!(err, IdentifierParseError::InvalidFormat { .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_format_preserves_unicode() {
        let save_spec = parse_save_format("🏷️unicode:📁path").unwrap();
        assert_eq!(save_spec.tag, "🏷️unicode");
        assert_eq!(save_spec.path, "📁path");

        let restore_spec = parse_restore_format("🏷️unicode:📁path").unwrap();
        assert_eq!(restore_spec.tag, "🏷️unicode");
        assert_eq!(restore_spec.path.as_deref(), Some("📁path"));
    }

    #[test]
    fn get_optimal_concurrency_respects_operation_count() {
        assert_eq!(get_optimal_concurrency(1, "save"), 1);
        assert!(get_optimal_concurrency(8, "restore") >= 2);
    }

    #[test]
    fn calculate_percent_clamps_between_zero_and_hundred() {
        assert_eq!(calculate_percent(0, 0), 0.0);
        assert_eq!(calculate_percent(50, 100), 50.0);
        assert_eq!(calculate_percent(200, 100), 100.0);
    }
}
