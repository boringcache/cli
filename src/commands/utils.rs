use crate::config::Config;
use crate::ui;
use anyhow::Result;
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

    if let Some(workspace) = crate::config::env_var("BORINGCACHE_DEFAULT_WORKSPACE") {
        return Ok(workspace);
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

pub fn resolve_encryption_config(
    workspace: &str,
    explicit_recipient: Option<String>,
) -> Result<(bool, Option<String>)> {
    if let Some(recipient) = explicit_recipient {
        return Ok((true, Some(recipient)));
    }

    if let Ok(config) = Config::load() {
        if let Some(ws_encryption) = config.get_workspace_encryption(workspace) {
            if ws_encryption.enabled && !ws_encryption.recipient.is_empty() {
                return Ok((true, Some(ws_encryption.recipient.clone())));
            }
        }
    }

    Ok((false, None))
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
        "save" => std::cmp::max(4, cpu_count),
        "restore" => std::cmp::max(4, cpu_count),
        _ => 4,
    };

    let platform_adjusted = if cfg!(target_os = "macos") {
        base_concurrency + 2
    } else if cfg!(target_os = "windows") {
        std::cmp::max(2, base_concurrency - 1)
    } else {
        base_concurrency
    };

    let hard_cap = match operation_type {
        "save" => 16,
        "restore" => 24,
        _ => 16,
    };

    std::cmp::min(std::cmp::min(platform_adjusted, hard_cap), operation_count)
}

pub fn display_concurrency_info(max_concurrent: usize, operation_type: &str) {
    ui::info(&format!(
        "Using {max_concurrent} concurrent {operation_type} operations"
    ));
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
}
