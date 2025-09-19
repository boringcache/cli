use crate::config::Config;
use crate::ui::CleanUI;
use anyhow::Result;

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

    match Config::load() {
        Ok(config) => {
            if let Some(default_workspace) = config.default_workspace {
                Ok(default_workspace)
            } else {
                Err(anyhow::anyhow!("No workspace specified and no default workspace configured. Use --workspace or set a default with 'boringcache config set default_workspace <name>'"))
            }
        }
        Err(_) => {
            Err(anyhow::anyhow!("No workspace specified and config not found. Use --workspace or run 'boringcache auth' first"))
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedIdentifier {
    pub key: String,
    pub path: Option<String>,
    pub tag: Option<String>,
}

pub fn parse_save_format(path_tag_string: &str) -> ParsedIdentifier {
    let trimmed = path_tag_string.trim();
    if trimmed.is_empty() {
        return ParsedIdentifier {
            key: "".to_string(),
            path: None,
            tag: None,
        };
    }

    let parts: Vec<&str> = trimmed.split(':').collect();

    if parts.len() != 2 {
        if parts.len() == 3 && parts[0].len() == 1 && parts[0].chars().all(char::is_alphabetic) {
            let path = format!("{}:{}", parts[0], parts[1]);
            return ParsedIdentifier {
                key: "".to_string(),
                path: Some(path),
                tag: Some(parts[2].to_string()),
            };
        }

        if std::env::var("CARGO_TEST_BINARY_NAME").is_ok() {
            return ParsedIdentifier {
                key: "".to_string(),
                path: None,
                tag: None,
            };
        }

        CleanUI::error(&format!("Invalid path:tag format: '{path_tag_string}'"));
        CleanUI::error("Expected format: path:tag (e.g., vendor/bundle:ruby-deps)");
        std::process::exit(1);
    }

    ParsedIdentifier {
        key: "".to_string(), // Will be generated from path content hash
        path: Some(parts[0].to_string()),
        tag: Some(parts[1].to_string()),
    }
}

pub fn parse_restore_format(tag_path_string: &str) -> ParsedIdentifier {
    let trimmed = tag_path_string.trim();
    if trimmed.is_empty() {
        return ParsedIdentifier {
            key: "".to_string(),
            path: None,
            tag: None,
        };
    }

    let parts: Vec<&str> = trimmed.split(':').collect();
    match parts.len() {
        1 => {
            ParsedIdentifier {
                key: "".to_string(), // Will be resolved from tag
                path: None,          // Will default to current directory
                tag: Some(parts[0].to_string()),
            }
        }
        2 => {
            ParsedIdentifier {
                key: "".to_string(), // Will be resolved from tag
                path: Some(parts[1].to_string()),
                tag: Some(parts[0].to_string()),
            }
        }
        _ => {
            let tag = parts[0];
            let path = parts[1..].join(":");
            ParsedIdentifier {
                key: "".to_string(), // Will be resolved from tag
                path: Some(path),
                tag: Some(tag.to_string()),
            }
        }
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
    CleanUI::info(&format!(
        "🔧 Using {max_concurrent} concurrent {operation_type} operations"
    ));
}

pub fn validate_tag_name(tag: &str) -> Result<()> {
    if tag.is_empty() {
        anyhow::bail!("Tag cannot be empty");
    }

    if tag.len() > 128 {
        anyhow::bail!("Tag '{}' is too long (max 128 characters)", tag);
    }

    let valid_chars = tag
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');

    if !valid_chars {
        anyhow::bail!(
            "Tag '{}' contains invalid characters. Only alphanumeric characters, dots (.), dashes (-), and underscores (_) are allowed",
            tag
        );
    }

    if tag.starts_with('.') || tag.starts_with('-') {
        anyhow::bail!("Tag '{}' cannot start with '.' or '-'", tag);
    }

    if tag.ends_with('.') || tag.ends_with('-') {
        anyhow::bail!("Tag '{}' cannot end with '.' or '-'", tag);
    }

    if tag.contains("..") {
        anyhow::bail!("Tag '{}' cannot contain consecutive dots (..)", tag);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_save_format_valid_path_tag() {
        let result = parse_save_format("vendor/bundle:ruby-deps");
        assert_eq!(result.key, "");
        assert_eq!(result.path, Some("vendor/bundle".to_string()));
        assert_eq!(result.tag, Some("ruby-deps".to_string()));
    }

    #[test]
    fn test_parse_save_format_absolute_path() {
        let result = parse_save_format("/usr/local/bin:my-tools");
        assert_eq!(result.key, "");
        assert_eq!(result.path, Some("/usr/local/bin".to_string()));
        assert_eq!(result.tag, Some("my-tools".to_string()));
    }

    #[test]
    fn test_parse_save_format_home_path() {
        let result = parse_save_format("~/.config/app:config-v1");
        assert_eq!(result.key, "");
        assert_eq!(result.path, Some("~/.config/app".to_string()));
        assert_eq!(result.tag, Some("config-v1".to_string()));
    }

    #[test]
    fn test_parse_save_format_complex_paths() {
        let examples = vec![
            ("./node_modules:node-deps", "./node_modules", "node-deps"),
            ("build/output:build-v1.0", "build/output", "build-v1.0"),
            ("dist:production-build", "dist", "production-build"),
        ];

        for (input, expected_path, expected_tag) in examples {
            let result = parse_save_format(input);
            assert_eq!(result.key, "", "Key should be empty for input: {}", input);
            assert_eq!(
                result.path,
                Some(expected_path.to_string()),
                "Failed for input: {}",
                input
            );
            assert_eq!(
                result.tag,
                Some(expected_tag.to_string()),
                "Failed for input: {}",
                input
            );
        }
    }

    #[test]
    fn test_parse_save_format_with_spaces() {
        let result = parse_save_format("  vendor/bundle:ruby-deps  ");
        assert_eq!(result.key, "");
        assert_eq!(result.path, Some("vendor/bundle".to_string()));
        assert_eq!(result.tag, Some("ruby-deps".to_string()));
    }

    #[test]
    fn test_parse_save_format_windows_paths() {
        let result = parse_save_format("C:\\Program Files\\App:windows-app");
        assert_eq!(result.key, "");
        assert_eq!(result.path, Some("C:\\Program Files\\App".to_string()));
        assert_eq!(result.tag, Some("windows-app".to_string()));
    }

    #[test]
    fn test_parse_save_format_empty_returns_empty() {
        let result = parse_save_format("");
        assert_eq!(result.key, "");
        assert_eq!(result.path, None);
        assert_eq!(result.tag, None);
    }

    #[test]
    fn test_parse_restore_format_tag_only() {
        let result = parse_restore_format("ruby-deps");
        assert_eq!(result.key, "");
        assert_eq!(result.path, None);
        assert_eq!(result.tag, Some("ruby-deps".to_string()));
    }

    #[test]
    fn test_parse_restore_format_tag_with_path() {
        let result = parse_restore_format("ruby-deps:vendor/bundle");
        assert_eq!(result.key, "");
        assert_eq!(result.path, Some("vendor/bundle".to_string()));
        assert_eq!(result.tag, Some("ruby-deps".to_string()));
    }

    #[test]
    fn test_parse_restore_format_tag_with_current_dir() {
        let result = parse_restore_format("node-deps:.");
        assert_eq!(result.key, "");
        assert_eq!(result.path, Some(".".to_string()));
        assert_eq!(result.tag, Some("node-deps".to_string()));
    }

    #[test]
    fn test_parse_restore_format_tag_with_home_path() {
        let result = parse_restore_format("config:~/.config/app");
        assert_eq!(result.key, "");
        assert_eq!(result.path, Some("~/.config/app".to_string()));
        assert_eq!(result.tag, Some("config".to_string()));
    }

    #[test]
    fn test_parse_restore_format_complex_paths_with_colons() {
        let result = parse_restore_format("windows-app:C:\\Program Files\\App");
        assert_eq!(result.key, "");
        assert_eq!(result.path, Some("C:\\Program Files\\App".to_string()));
        assert_eq!(result.tag, Some("windows-app".to_string()));
    }

    #[test]
    fn test_parse_restore_format_many_colons() {
        let result = parse_restore_format("my-tag:complex:path:with:colons");
        assert_eq!(result.key, "");
        assert_eq!(result.path, Some("complex:path:with:colons".to_string()));
        assert_eq!(result.tag, Some("my-tag".to_string()));
    }

    #[test]
    fn test_parse_restore_format_empty() {
        let result = parse_restore_format("");
        assert_eq!(result.key, "");
        assert_eq!(result.path, None);
        assert_eq!(result.tag, None);
    }

    #[test]
    fn test_real_world_save_examples() {
        let examples = vec![
            ("vendor/bundle:ruby-deps", "vendor/bundle", "ruby-deps"),
            ("node_modules:node-deps", "node_modules", "node-deps"),
            (
                "~/.boringcache/ruby-3.4.4:ruby-3.4.4-ubuntu22.04",
                "~/.boringcache/ruby-3.4.4",
                "ruby-3.4.4-ubuntu22.04",
            ),
            (
                "build output:path-with-spaces",
                "build output",
                "path-with-spaces",
            ),
        ];

        for (input, expected_path, expected_tag) in examples {
            let result = parse_save_format(input);
            assert_eq!(
                result.path,
                Some(expected_path.to_string()),
                "Path failed for: {}",
                input
            );
            assert_eq!(
                result.tag,
                Some(expected_tag.to_string()),
                "Tag failed for: {}",
                input
            );
        }
    }

    #[test]
    fn test_real_world_restore_examples() {
        let examples = vec![
            (
                "ruby-deps:vendor/bundle",
                "ruby-deps",
                Some("vendor/bundle"),
            ),
            ("node-deps:node_modules", "node-deps", Some("node_modules")),
            (
                "ruby-3.4.4-ubuntu22.04:~/.boringcache/ruby-3.4.4",
                "ruby-3.4.4-ubuntu22.04",
                Some("~/.boringcache/ruby-3.4.4"),
            ),
            (
                "build-2025-09-06:./out dir",
                "build-2025-09-06",
                Some("./out dir"),
            ),
            ("my-cache", "my-cache", None), // Tag only, restore to current dir
        ];

        for (input, expected_tag, expected_path) in examples {
            let result = parse_restore_format(input);
            assert_eq!(
                result.tag,
                Some(expected_tag.to_string()),
                "Tag failed for: {}",
                input
            );
            assert_eq!(
                result.path,
                expected_path.map(|s| s.to_string()),
                "Path failed for: {}",
                input
            );
        }
    }

    #[test]
    fn test_parse_formats_with_special_characters() {
        let save_result = parse_save_format("path-with-dashes:tag_with_underscores");
        assert_eq!(save_result.path, Some("path-with-dashes".to_string()));
        assert_eq!(save_result.tag, Some("tag_with_underscores".to_string()));

        let restore_result = parse_restore_format("tag_with_underscores:path-with-dashes");
        assert_eq!(restore_result.tag, Some("tag_with_underscores".to_string()));
        assert_eq!(restore_result.path, Some("path-with-dashes".to_string()));
    }

    #[test]
    fn test_parse_formats_with_unicode() {
        let save_result = parse_save_format("📁unicode-path:🏷️unicode-tag");
        assert_eq!(save_result.path, Some("📁unicode-path".to_string()));
        assert_eq!(save_result.tag, Some("🏷️unicode-tag".to_string()));
    }

    #[test]
    fn test_get_optimal_concurrency_save() {
        let result = get_optimal_concurrency(10, "save");
        assert!(result >= 2, "Save concurrency should be at least 2");
        assert!(result <= 8, "Concurrency should not exceed 8");
    }

    #[test]
    fn test_get_optimal_concurrency_restore() {
        let result = get_optimal_concurrency(10, "restore");
        assert!(result >= 2, "Restore concurrency should be at least 2");
        assert!(result <= 8, "Concurrency should not exceed 8");
    }

    #[test]
    fn test_get_optimal_concurrency_limited_by_operation_count() {
        let result = get_optimal_concurrency(1, "save");
        assert_eq!(result, 1, "Concurrency should not exceed operation count");

        let result = get_optimal_concurrency(2, "restore");
        assert!(result <= 2, "Concurrency should not exceed operation count");
    }

    #[test]
    fn test_get_optimal_concurrency_unknown_type() {
        let result = get_optimal_concurrency(10, "unknown");
        assert_eq!(result, 3, "Unknown operation type should default to 3");
    }
}
